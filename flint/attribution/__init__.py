"""Verifiable trust attribution (manuscript §V, Definitions 5 and 6).

Theorem 2 reduces every evasion of f_flow to two forgeries: raising an untrusted
entity's integrity label to trusted, or presenting an unauthorised activity as an
endorser. This module makes both claims verifiable, so a graph can be checked
before the detector believes it:

* **Signed source attribution (Def. 5).** The recorder, holding sk_rec, signs each
  entity's label together with the entity and the channel it arrived on:
  σ_e = sign(e ‖ c ‖ λ(e)). A ``trusted`` label is believed only if σ_e verifies;
  a missing or invalid signature reads as ``untrusted`` (fail-closed).
* **Capability-bound endorsement (Def. 6).** The principal that owns an
  authorisation, holding sk_cap, issues a capability τ = sign(action ‖ scope). An
  activity is admitted to D only if it carries a valid τ issued for its action.

``verify_attribution(G, labels=..., capabilities=...)`` applies both rules and
returns a new graph in which every unverified claim has been withdrawn. f_flow is
unchanged and runs on that graph: the hardening is entirely in what the detector
is willing to believe, not in what it computes.

FLINT never holds keys. Signing and verification go through the small ``Signer``
and ``Verifier`` protocols, so a deployment can keep its keys in a hardware or OS
keystore. ``flint.attribution.ed25519`` provides Ed25519 implementations (the
``[attribution]`` extra). The two keys are deliberately separate parameters: they
attest different things, and Theorem 3 needs neither to imply the other.

* **Relation commitment (§V's closing remark).** Labels bind to entities, not to
  edges, so a relation could still be dropped from the record between recording
  and detection, breaking the flow path. The recorder therefore also signs, with
  sk_rec, a Merkle root (RFC 6962 hashing) over every flow edge it emitted.
  ``verify_attribution(..., relations=token)`` recomputes the root and reports
  ``record_complete``; an edge dropped, added or altered after recording makes
  it False, which a deployment treats as an alert. It cannot restore a relation
  the recorder never observed: the record must still be flow-complete (A4).

Out of scope, as in the paper: compromise of sk_rec or sk_cap (whoever holds a key
can sign anything it covers). Signatures make labels unforgeable, not correct.

Wire format (version 1)
-----------------------
Signed messages are length-prefixed byte strings under a domain-separation tag, so
no two different field tuples encode to the same bytes and a signature from one
context can never verify in the other::

    message = TAG || for each field: uint32_be(len(field)) || field

Entity attributes: ``adprov:source_channel`` (c), ``adprov:label_kid``,
``adprov:label_sig`` (base64url, unpadded). The entity's ``adprov:content_hash``,
when present, is also signed, binding the label to the content as well as the id.

Activity attributes: ``adprov:action`` and ``adprov:capability``, a token string
``flintcap1.<base64url(payload JSON)>.<base64url(signature)>``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import networkx as nx

from flint.spec import (
    ENDORSER,
    INTEGRITY_KEY,
    NEUTRAL,
    ROLE_KEY,
    SINK,
    TRUSTED,
    UNTRUSTED,
    literal_value,
)

# --- vocabulary --------------------------------------------------------------

CHANNEL_KEY = "adprov:source_channel"
CONTENT_HASH_KEY = "adprov:content_hash"
LABEL_KID_KEY = "adprov:label_kid"
LABEL_SIG_KEY = "adprov:label_sig"
ACTION_KEY = "adprov:action"
CAPABILITY_KEY = "adprov:capability"

SOURCE_TAG = b"FLINT/source-label/v1\x00"
CAPABILITY_TAG = b"FLINT/capability/v1\x00"
RELATIONS_TAG = b"FLINT/relations/v1\x00"
RECORD_TAG = b"FLINT/record/v1\x00"
NODE_TAG = b"FLINT/node/v1\x00"
EDGE_TAG = b"FLINT/edge/v1\x00"
TOKEN_PREFIX = "flintcap1"
RELATIONS_PREFIX = "flintrel1"
RECORD_PREFIX = "flintrec1"
ARGS_KEY = "adprov:args"
ARG_SCOPE_PREFIX = "arg:"

ScopeValue = str | Sequence[str]


# --- key interfaces ----------------------------------------------------------

@runtime_checkable
class Signer(Protocol):
    """Signs messages under one key, named by ``kid`` so verifiers can find it."""

    @property
    def kid(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


@runtime_checkable
class Verifier(Protocol):
    """Checks a signature against the key named ``kid``.

    Must return False, never raise, for an unknown or revoked ``kid`` or a bad
    signature: every failure reads as "not verified", which the callers turn into
    the fail-closed outcome.
    """

    def verify(self, kid: str, message: bytes, signature: bytes) -> bool: ...


# --- canonical messages ------------------------------------------------------

def _frame(tag: bytes, *fields: bytes) -> bytes:
    out = bytearray(tag)
    for f in fields:
        out += len(f).to_bytes(4, "big")
        out += f
    return bytes(out)


def source_label_message(
    entity_id: str, channel: str, label: str, content_hash: str | None = None
) -> bytes:
    """The bytes σ_e signs: entity ‖ channel ‖ label ‖ content hash (Def. 5)."""
    return _frame(
        SOURCE_TAG,
        entity_id.encode(), channel.encode(), label.encode(), (content_hash or "").encode(),
    )


def _scope_bytes(scope: Mapping[str, ScopeValue]) -> bytes:
    parts: list[bytes] = []
    for key in sorted(scope):
        value = scope[key]
        if isinstance(value, str):
            parts += [key.encode(), b"s", value.encode()]
        else:
            items = list(value)
            if not all(isinstance(v, str) for v in items):
                raise TypeError(f"scope[{key!r}] must be a string or a list of strings")
            parts += [key.encode(), b"l", str(len(items)).encode(), *(v.encode() for v in items)]
    return _frame(b"", *parts)


def capability_message(
    action: str,
    scope: Mapping[str, ScopeValue],
    expires_at: int | None,
    nonce: str,
) -> bytes:
    """The bytes τ signs: action ‖ scope ‖ expiry ‖ nonce (Def. 6)."""
    return _frame(
        CAPABILITY_TAG,
        action.encode(),
        _scope_bytes(scope),
        b"" if expires_at is None else str(expires_at).encode(),
        nonce.encode(),
    )


# --- relation commitment (Merkle root over the flow edges) ---------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle tree hash: leaf = H(0x00 || d), node = H(0x01 || l || r)."""
    if not leaves:
        return _sha256(b"")
    level = [_sha256(b"\x00" + leaf) for leaf in leaves]

    def mth(nodes: list[bytes]) -> bytes:
        if len(nodes) == 1:
            return nodes[0]
        k = 1 << ((len(nodes) - 1).bit_length() - 1)   # largest power of two < n
        return _sha256(b"\x01" + mth(nodes[:k]) + mth(nodes[k:]))

    return mth(level)


def relation_leaves(G: nx.DiGraph) -> list[bytes]:
    """The committed set: one leaf per flow edge (relation, from, to), sorted."""
    leaves = {
        _frame(EDGE_TAG, str(d.get("relation", "")).encode(), str(u).encode(), str(v).encode())
        for u, v, d in G.edges(data=True)
    }
    return sorted(leaves)


def relations_root(G: nx.DiGraph) -> bytes:
    """Merkle root over ``relation_leaves(G)``; independent of edge order."""
    return _merkle_root(relation_leaves(G))


def relations_message(trace_id: str, root: bytes, count: int) -> bytes:
    """The bytes the recorder signs to commit to a trace's relations."""
    return _frame(RELATIONS_TAG, trace_id.encode(), root, str(count).encode())


def _attr_text(value: Any) -> bytes:
    """A node attribute as committed bytes: strings as-is, absent as empty."""
    v = literal_value(value)
    if v is None:
        return b""
    if isinstance(v, str):
        return v.encode()
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_leaves(G: nx.DiGraph) -> list[bytes]:
    """The whole record's leaves: every flow edge, and every node with the labels
    the detector reads (an entity's integrity; an activity's role and action)."""
    leaves = set(relation_leaves(G))
    for n, d in G.nodes(data=True):
        node_type = d.get("node_type")
        fields = [_attr_text(node_type), str(n).encode()]
        if node_type == "entity":
            fields.append(_attr_text(d.get(INTEGRITY_KEY)))
        elif node_type == "activity":
            fields += [_attr_text(d.get(ROLE_KEY)), _attr_text(d.get(ACTION_KEY))]
        leaves.add(_frame(NODE_TAG, *fields))
    return sorted(leaves)


# commitment kind -> (domain tag, leaf function, name used in messages)
_COMMITMENTS: dict[str, tuple[bytes, Callable[[nx.DiGraph], list[bytes]], str]] = {
    RELATIONS_PREFIX: (RELATIONS_TAG, relation_leaves, "relation"),
    RECORD_PREFIX: (RECORD_TAG, record_leaves, "record"),
}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- producer side -----------------------------------------------------------

def sign_source_label(
    signer: Signer,
    entity_id: str,
    channel: str,
    label: str,
    content_hash: str | None = None,
) -> dict[str, str]:
    """Attributes the recorder adds to an entity: its label, channel and σ_e.

    Merge the result into the entity's PROV-JSON attributes.
    """
    message = source_label_message(entity_id, channel, label, content_hash)
    return {
        INTEGRITY_KEY: label,
        CHANNEL_KEY: channel,
        LABEL_KID_KEY: signer.kid,
        LABEL_SIG_KEY: _b64(signer.sign(message)),
    }


def issue_capability(
    signer: Signer,
    action: str,
    scope: Mapping[str, ScopeValue],
    *,
    expires_at: int | None = None,
    nonce: str | None = None,
) -> str:
    """Issue τ for one sanctioned action, as a token string for ``adprov:capability``.

    ``scope`` says what the authorisation covers (e.g. the trace and the hashes of
    the approved artefacts); ``expires_at`` is a Unix time in seconds. Each token
    gets a fresh random nonce, so one approval cannot endorse two activities.
    """
    nonce = nonce if nonce is not None else secrets.token_hex(16)
    scope_json = {k: (v if isinstance(v, str) else list(v)) for k, v in scope.items()}
    message = capability_message(action, scope_json, expires_at, nonce)
    payload = {
        "kid": signer.kid, "action": action, "scope": scope_json,
        "exp": expires_at, "nonce": nonce,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{TOKEN_PREFIX}.{_b64(body.encode())}.{_b64(signer.sign(message))}"


def _commit(prefix: str, signer: Signer, G: nx.DiGraph, trace_id: str) -> str:
    tag, leaves_fn, _ = _COMMITMENTS[prefix]
    leaves = leaves_fn(G)
    root, count = _merkle_root(leaves), len(leaves)
    payload = {"kid": signer.kid, "trace": trace_id, "root": _b64(root), "count": count}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = signer.sign(_frame(tag, trace_id.encode(), root, str(count).encode()))
    return f"{prefix}.{_b64(body.encode())}.{_b64(sig)}"


def commit_relations(signer: Signer, G: nx.DiGraph, trace_id: str) -> str:
    """The recorder's signed commitment to every flow edge of ``G`` (use sk_rec).

    ``G`` is the graph as emitted, i.e. ``load_prov_graph(doc)`` of the document the
    recorder writes. Store the returned token with the trace and pass it to
    ``verify_attribution(..., relations=token, trace_id=trace_id)``.
    """
    return _commit(RELATIONS_PREFIX, signer, G, trace_id)


def commit_record(signer: Signer, G: nx.DiGraph, trace_id: str) -> str:
    """Like ``commit_relations``, but over the whole record (use sk_rec).

    Besides every flow edge it covers every node, each entity's integrity label,
    and each activity's role and action. A sink demoted to neutral, a node added
    or removed, or a label changed after recording then fails the check, as an
    omitted edge does. Pass the token as ``verify_attribution(..., relations=token)``.
    """
    return _commit(RECORD_PREFIX, signer, G, trace_id)


def _check_relations(
    G: nx.DiGraph, token: object, labels: Verifier, trace_id: str | None
) -> str | None:
    """None if ``token`` is a valid commitment to exactly what G records."""
    if not isinstance(token, str):
        return "no relation commitment"
    parts = token.split(".")
    if len(parts) != 3 or parts[0] not in _COMMITMENTS:
        return "malformed relation commitment"
    tag, leaves_fn, kind = _COMMITMENTS[parts[0]]
    try:
        payload = json.loads(_unb64(parts[1]).decode(), object_pairs_hook=_no_duplicates)
        signature, root = _unb64(parts[2]), _unb64(payload["root"])
        kid, trace, count = payload["kid"], payload["trace"], payload["count"]
    except (ValueError, UnicodeDecodeError, KeyError, TypeError, AttributeError):
        return f"malformed {kind} commitment"
    if not (isinstance(kid, str) and isinstance(trace, str)
            and isinstance(count, int) and not isinstance(count, bool)):
        return f"malformed {kind} commitment"
    if not labels.verify(kid, _frame(tag, trace.encode(), root, str(count).encode()), signature):
        return f"{kind} commitment does not verify"
    if trace_id is not None and trace != trace_id:
        return f"{kind} commitment is for another trace"
    leaves = leaves_fn(G)
    if _merkle_root(leaves) != root or len(leaves) != count:
        return ("recorded relations differ from the committed set" if kind == "relation"
                else "recorded graph differs from the committed record")
    return None


# --- capability scope over arguments -----------------------------------------

def _scope_text(value: Any) -> ScopeValue:
    """An argument value as a scope value: strings as-is, lists element-wise,
    anything else as canonical JSON."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return [x if isinstance(x, str) else json.dumps(x, sort_keys=True) for x in value]
    return json.dumps(value, sort_keys=True)


def argument_scope(args: Mapping[str, Any], names: Collection[str] | None = None) -> dict[str, ScopeValue]:
    """Scope entries that bind a capability to argument values (``arg:<name>``).

    ``issue_capability(signer, action, {"trace": t, **argument_scope(args, ["recipients"])})``
    issues a capability that only an activity recording those exact arguments in
    ``adprov:args`` can use: a capability "bound to the recipient".
    """
    keys = list(args) if names is None else [k for k in names if k in args]
    return {f"{ARG_SCOPE_PREFIX}{k}": _scope_text(args[k]) for k in keys}


def _activity_args(d: Mapping[str, Any]) -> Mapping[str, Any] | None:
    raw = literal_value(d.get(ARGS_KEY))
    if isinstance(raw, Mapping):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw, object_pairs_hook=_no_duplicates)
        except ValueError:
            return None
        return parsed if isinstance(parsed, Mapping) else None
    return None


# --- verification ------------------------------------------------------------

@dataclass(frozen=True)
class Capability:
    """A decoded (not yet verified) capability token."""

    kid: str
    action: str
    scope: Mapping[str, ScopeValue]
    expires_at: int | None
    nonce: str
    signature: bytes

    @property
    def message(self) -> bytes:
        return capability_message(self.action, self.scope, self.expires_at, self.nonce)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def decode_capability(token: object) -> Capability | None:
    """Parse a token string; None if it is not a well-formed version-1 token."""
    if not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        return None
    try:
        payload = json.loads(_unb64(parts[1]).decode(), object_pairs_hook=_no_duplicates)
        signature = _unb64(parts[2])
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict) or set(payload) != {"kid", "action", "scope", "exp", "nonce"}:
        return None
    kid, action, scope, exp, nonce = (payload[k] for k in ("kid", "action", "scope", "exp", "nonce"))
    if not (isinstance(kid, str) and isinstance(action, str) and isinstance(nonce, str)
            and isinstance(scope, dict)
            and (exp is None or (isinstance(exp, int) and not isinstance(exp, bool)))):
        return None
    for v in scope.values():
        if not (isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))):
            return None
    return Capability(kid, action, scope, exp, nonce, signature)


ScopeCheck = Callable[[str, Mapping[str, Any], Capability], bool]


@dataclass(frozen=True)
class AttributionResult:
    """``verify_attribution``'s output: the believable graph and what was withdrawn."""

    graph: nx.DiGraph
    downgraded: Mapping[str, str] = field(default_factory=dict)
    """Entities whose ``trusted`` label was withdrawn, with the reason."""
    rejected_endorsers: Mapping[str, str] = field(default_factory=dict)
    """Activities removed from D (now ``neutral``), with the reason."""
    added_sinks: Sequence[str] = ()
    """Activities made sinks by ``sink_actions`` although they did not claim it."""
    record_complete: bool | None = None
    """With ``relations=``: whether the graph's flow edges are exactly the
    committed set. None when no commitment was checked. False means a relation
    was omitted or added after recording: treat it as an alert, since f_flow
    cannot see a flow whose edge is missing."""
    record_issue: str | None = None
    """Why ``record_complete`` is False."""

    @property
    def alert(self) -> bool:
        """f_flow on the verified graph, or an incomplete record: the deployed decision."""
        from flint.layer1_graph.flow import check_flow
        return self.record_complete is False or check_flow(self.graph)


def _check_label(n: str, d: Mapping[str, Any], labels: Verifier) -> str | None:
    """None if the trusted label verifies, else the reason it does not."""
    channel, kid, sig = (literal_value(d.get(k)) for k in (CHANNEL_KEY, LABEL_KID_KEY, LABEL_SIG_KEY))
    if sig is None:
        return "no label signature"
    if not (isinstance(channel, str) and isinstance(kid, str) and isinstance(sig, str)):
        return "malformed label signature"
    content_hash = literal_value(d.get(CONTENT_HASH_KEY))
    if content_hash is not None and not isinstance(content_hash, str):
        return "malformed content hash"
    try:
        signature = _unb64(sig)
    except ValueError:
        return "malformed label signature"
    message = source_label_message(n, channel, TRUSTED, content_hash)
    if not labels.verify(kid, message, signature):
        return "label signature does not verify"
    return None


def _check_capability(
    n: str,
    d: Mapping[str, Any],
    cap: Capability | None,
    capabilities: Verifier,
    trace_id: str | None,
    now: float,
    scope_check: ScopeCheck | None,
) -> str | None:
    if CAPABILITY_KEY not in d:
        return "no capability"
    if cap is None:
        return "malformed capability"
    action = literal_value(d.get(ACTION_KEY))
    if not isinstance(action, str):
        return "endorser declares no adprov:action"
    if cap.action != action:
        return f"capability is for {cap.action!r}, not {action!r}"
    if not capabilities.verify(cap.kid, cap.message, cap.signature):
        return "capability signature does not verify"
    if cap.expires_at is not None and now >= cap.expires_at:
        return "capability expired"
    if trace_id is not None and cap.scope.get("trace") != trace_id:
        return "capability scope is for another trace"
    bound = {k[len(ARG_SCOPE_PREFIX):]: v for k, v in cap.scope.items()
             if k.startswith(ARG_SCOPE_PREFIX)}
    if bound:
        args = _activity_args(d)
        if args is None:
            return "capability binds arguments the activity does not record"
        for name, want in bound.items():
            if name not in args or _scope_text(args[name]) != want:
                return f"capability does not cover argument {name!r}"
    if scope_check is not None and not scope_check(n, d, cap):
        return "capability scope does not cover this activity"
    return None


def verify_attribution(
    G: nx.DiGraph,
    *,
    labels: Verifier,
    capabilities: Verifier,
    trace_id: str | None = None,
    now: float | None = None,
    scope_check: ScopeCheck | None = None,
    sink_actions: Collection[str] | None = None,
    relations: str | None = None,
) -> AttributionResult:
    """Withdraw every trust claim in ``G`` that does not verify; ``G`` is not modified.

    * An entity stays ``trusted`` only if it is labelled so and its
      ``adprov:label_sig`` verifies under ``labels`` (the recorder's keys). Any
      other entity, including an unlabelled one, becomes ``untrusted`` (Def. 5,
      fail-closed). ``untrusted`` labels need no signature: claiming less trust can
      never hide a flow.
    * An activity claiming ``endorser`` stays in D only if its ``adprov:capability``
      verifies under ``capabilities`` (the authorising principal's keys), was issued
      for the activity's ``adprov:action``, has not expired at ``now``, is scoped to
      ``trace_id`` (when given, via ``scope["trace"]``), and passes ``scope_check``
      (when given). Otherwise it becomes ``neutral`` (Def. 6). A capability carried
      by more than one activity admits none of them: one approval, one endorsement.
      (Copying a token onto a second activity can therefore cancel an endorsement,
      which only ever adds alerts.)
    * With ``sink_actions``, any activity whose ``adprov:action`` is listed is a sink
      whatever role it claims. The sink set is policy, not a claim of the record, so
      a record cannot drop a sink by relabelling it.

    * With ``relations``, the recorder's ``commit_relations`` token is checked
      against ``G``'s flow edges (under ``labels``: the recorder signs it).
      ``result.record_complete`` is False if any edge was omitted or added.

    Use ``result.alert`` for the deployed decision (an incomplete record, or f_flow
    on the verified graph), or run ``f_flow`` on ``result.graph`` yourself.
    """
    now = time.time() if now is None else now
    H = G.copy()
    downgraded: dict[str, str] = {}
    rejected: dict[str, str] = {}
    added_sinks: list[str] = []

    for n, d in H.nodes(data=True):
        if d.get("node_type") != "entity":
            continue
        label = literal_value(d.get(INTEGRITY_KEY))
        if label == UNTRUSTED:
            continue
        reason = (
            _check_label(n, d, labels) if label == TRUSTED
            else "no integrity label" if label is None
            else f"unrecognised integrity label {label!r}"
        )
        if reason is not None:
            d[INTEGRITY_KEY] = UNTRUSTED
            downgraded[n] = reason

    claimed = [n for n, d in H.nodes(data=True)
               if d.get("node_type") == "activity" and literal_value(d.get(ROLE_KEY)) == ENDORSER]
    decoded = {n: decode_capability(literal_value(H.nodes[n].get(CAPABILITY_KEY))) for n in claimed}
    nonce_uses: dict[tuple[str, str], int] = {}
    for cap in decoded.values():
        if cap is not None:
            nonce_uses[(cap.kid, cap.nonce)] = nonce_uses.get((cap.kid, cap.nonce), 0) + 1
    for n in claimed:
        d = H.nodes[n]
        cap = decoded[n]
        reason = _check_capability(n, d, cap, capabilities, trace_id, now, scope_check)
        if reason is None and cap is not None and nonce_uses[(cap.kid, cap.nonce)] > 1:
            reason = "capability presented by more than one activity"
        if reason is not None:
            d[ROLE_KEY] = NEUTRAL
            rejected[n] = reason

    if sink_actions is not None:
        policy = frozenset(sink_actions)
        for n, d in H.nodes(data=True):
            if d.get("node_type") != "activity" or literal_value(d.get(ACTION_KEY)) not in policy:
                continue
            role = literal_value(d.get(ROLE_KEY))
            if role == SINK:
                continue
            if role == ENDORSER:
                # The sink wins: a node has one role, and an endorsement placed on the
                # privileged action itself would license whatever flows into it.
                rejected[n] = "action is a sink under the policy"
            d[ROLE_KEY] = SINK
            added_sinks.append(n)

    record_complete: bool | None = None
    record_issue: str | None = None
    if relations is not None:
        record_issue = _check_relations(G, relations, labels, trace_id)
        record_complete = record_issue is None

    return AttributionResult(
        H, downgraded, rejected, tuple(added_sinks), record_complete, record_issue,
    )


__all__ = [
    "ACTION_KEY",
    "CAPABILITY_KEY",
    "CHANNEL_KEY",
    "LABEL_KID_KEY",
    "LABEL_SIG_KEY",
    "AttributionResult",
    "Capability",
    "Signer",
    "Verifier",
    "argument_scope",
    "capability_message",
    "commit_record",
    "commit_relations",
    "decode_capability",
    "issue_capability",
    "relations_root",
    "sign_source_label",
    "source_label_message",
    "verify_attribution",
]
