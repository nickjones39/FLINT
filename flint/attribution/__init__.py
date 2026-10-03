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

Out of scope, as in the paper: compromise of sk_rec or sk_cap (whoever holds a key
can sign anything it covers), and a record that omits a relation altogether.
Signatures make labels unforgeable, not correct.

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
TOKEN_PREFIX = "flintcap1"

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

    Run ``f_flow`` on ``result.graph``.
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

    return AttributionResult(H, downgraded, rejected, tuple(added_sinks))


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
    "capability_message",
    "decode_capability",
    "issue_capability",
    "sign_source_label",
    "source_label_message",
    "verify_attribution",
]
