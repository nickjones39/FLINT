# FLINT input format

FLINT reads one [PROV-JSON](https://www.w3.org/submissions/prov-json/) document per
agent run. This page specifies what that document must contain for the detector to
judge it. It is written for anyone *producing* traces for FLINT; the vocabulary is
the one the [AgentDojo-PROV](https://doi.org/10.5281/zenodo.21052314) corpus uses,
and `flint/spec.py` holds the same names as constants.

## Namespace

| Prefix | URI |
|---|---|
| `adprov` | `https://nickjones39.github.io/agentdojo-prov/ns#` |

Labels are read only under the `adprov:` prefix. Declaring it in the document's
`prefix` section is recommended but not required. Under `strict=True`, a document that
binds `adprov` to another URI, or binds this URI to a different prefix, is rejected,
because its labels would otherwise be silently skipped.

## Document sections

Under `strict=True`, only these top-level sections are accepted:

| Kind | Sections |
|---|---|
| namespaces | `prefix` |
| nodes | `entity`, `activity`, `agent` |
| flow relations | `used`, `wasGeneratedBy`, `wasDerivedFrom`, `wasInformedBy` |
| non-flow relations (ignored) | `wasAssociatedWith`, `wasAttributedTo`, `actedOnBehalfOf` |

Anything else is rejected, including a `bundle` and any other PROV relation
(`wasStartedBy`, `wasEndedBy`, `wasInvalidatedBy`, `wasInfluencedBy`, `hadMember`,
`specializationOf`, `alternateOf`, `mentionOf`, …). Each of these could carry a flow
FLINT does not model, so strict mode refuses the document rather than miss it. If your
producer needs one of them, express the flow with the four flow relations. The
default loader ignores these sections, as the published results did.

A record is normally one JSON object. PROV-JSON also allows a **list of objects**
when several records share an identifier, and FLINT accepts that too. Each instance
of a relation becomes an edge, and the instances of a node are merged into one node.
Under `strict=True`, instances that disagree on `adprov:integrity` or `adprov:role`
are rejected.

## Nodes

Nodes are the `entity`, `activity` and `agent` sections. An identifier must appear in
only one of them. `node_type` is reserved for FLINT's own use, so a document may not
use it as an attribute name. Attribute names must be strings.

### Entities — `adprov:integrity` (required)

FLINT implements the two-point integrity lattice {⊥, ⊤}. The paper's definition
allows any finite lattice, but there is no intermediate level here. A value other
than these two is unrecognised (see below), not a level in between.

| Value | Meaning |
|---|---|
| `untrusted` | ⊥: data from a channel the user does not control (tool output carrying external content: email bodies, web pages, files, messages, reviews). These are the flow sources. |
| `trusted` | ⊤: data from the user or a trusted channel. |

**A missing or unrecognised value is read as `untrusted`** under `strict=True`. Values
are case-sensitive, so `Trusted` is unrecognised. The loader records the original
value in `flint:integrity_defaulted` so the producer bug is visible. The default
loader (`strict=False`, the one the published results were produced with) instead
leaves an unlabelled entity out of the source set.

### Activities — `adprov:role` (required)

| Value | Meaning |
|---|---|
| `sink` | S: a privileged action, i.e. one that sends, writes a file, writes memory, executes code, or otherwise acts outside the agent. |
| `endorser` | D: a validation or approval step. A flow passing through an endorser is not reported. |
| `neutral` | Neither. |

Under `strict=True`, an activity with a missing or unrecognised role is **rejected**
(`ProvFormatError`). There is no safe default: reading it as `neutral` could hide a
sink, and reading it as `sink` would turn every unlabelled step into an alarm.

> Unless you verify them, endorsements are unauthenticated: anything labelled
> `endorser` is trusted to be one. That is the label forgery the manuscript's
> Theorem 2 identifies. See [Signed labels and capabilities](#signed-labels-and-capabilities-v03-flintattribution).

Roles exist only on activities: S and D are sets of activities. The detector ignores
an `adprov:role` on an entity or agent in either mode, and `strict=True` rejects it.
Without this rule, an endorser label mislabelled onto a data node would cut every
flow through it.

### Agents

Agents are loaded, but none of their labels are read.

## Parsing

Read files with `load_prov_graph_from_file`, or parse text with `parse_prov_json`,
rather than `json.loads`. Both raise `ProvFormatError` for anything unparseable:
invalid JSON, non-UTF-8 bytes, or nesting too deep to parse. A leading byte-order
mark is tolerated. Under `strict=True` they also reject **duplicate object keys**,
because parsers disagree on which value wins, so a label could read ⊥ to its
producer and ⊤ to FLINT. They also reject the non-standard `NaN` and `Infinity`
literals.

Label values may be bare strings (`"untrusted"`) or PROV-JSON typed literals
(`{"$": "untrusted", "type": "xsd:string"}`). Both are read the same way.

## Signed labels and capabilities (v0.3, `flint.attribution`)

Without these, FLINT believes every label in the document. That leaves the two
forgeries of the manuscript's Theorem 2 open: an untrusted entity relabelled
`trusted`, or an activity presented as an endorser. With them,
`verify_attribution` withdraws every claim that does not verify before `f_flow` runs
(manuscript §V, Definitions 5 and 6).

**Entity (Definition 5).** The recorder signs the label it assigns:

| Attribute | Value |
|---|---|
| `adprov:integrity` | the label, as above |
| `adprov:source_channel` | the channel the entity arrived on |
| `adprov:label_kid` | the id of the recorder key that signed |
| `adprov:label_sig` | base64url (unpadded) signature over entity id ‖ channel ‖ label ‖ `adprov:content_hash` |

An entity stays `trusted` only if this signature verifies under the recorder's keys.
A missing or invalid signature, a missing label or an unrecognised label all read
as `untrusted`. An `untrusted` label needs no signature.

**Endorser (Definition 6).** The principal that authorised the action issues a
capability:

| Attribute | Value |
|---|---|
| `adprov:role` | `endorser` |
| `adprov:action` | the sanctioned action, e.g. `approve_submission` |
| `adprov:capability` | `flintcap1.<base64url(payload)>.<base64url(signature)>` |

The payload holds the key id, the action, a scope, an optional expiry (Unix
seconds) and a nonce. An endorser stays in D only if all of the following hold:
- the capability verifies under the authorising principal's keys;
- it was issued for this activity's `adprov:action`;
- it has not expired;
- its scope matches the trace being checked (`scope["trace"]`), when a trace id is
  given;
- it passes any scope check the deployment supplies;
- no other activity carries the same capability.

Otherwise the activity is treated as `neutral`.

The two kinds of signature use **separate keys**, and `verify_attribution` takes
them separately. One attests where data came from, the other what a user
authorised. Neither verifies as the other.

**Omitted relations.** Signed labels bind to entities, not to edges, so a record
could still lose the one relation that carries a flow after it was recorded. The recorder therefore also
signs a commitment to the trace's relations with `flint.commit_relations`: a
Merkle root (RFC 6962 hashing) over every flow edge as (relation, from, to). The
commitment is stored alongside the trace and passed as
`verify_attribution(..., relations=token)`. If any edge was omitted, added or
retyped after recording, `result.record_complete` is False and `result.alert` is
True. A relation the recorder never observed cannot be recovered this way: the
record must still be flow-complete.

**Sinks.** The sink set is policy, not a claim of the record. Passing
`sink_actions` makes every activity whose `adprov:action` is listed a sink, so a
record cannot drop a sink by relabelling it.

Signatures use length-prefixed, domain-separated messages (see
`flint/attribution/__init__.py`), so they reproduce across implementations. FLINT
never holds keys: it signs and verifies through two small protocols, `Signer` and
`Verifier`. Ed25519 implementations are in `flint.attribution.ed25519` (the
`[attribution]` extra). Out of scope, as in the paper: a compromised signing key.

## Relations

The four relations below carry information flow and become directed edges. Their
endpoint fields are required, must be qualified-name strings, and under
`strict=True` must name a declared node of the stated type.

| Relation | Fields (type) | Flow edge |
|---|---|---|
| `used` | `prov:activity` (activity), `prov:entity` (entity) | entity → activity |
| `wasGeneratedBy` | `prov:entity` (entity), `prov:activity` (activity) | activity → entity |
| `wasDerivedFrom` | `prov:generatedEntity` (entity), `prov:usedEntity` (entity) | used → generated |
| `wasInformedBy` | `prov:informed` (activity), `prov:informant` (activity) | informant → informed |

`used` without `prov:entity` and `wasGeneratedBy` without `prov:activity` are valid
PROV, but FLINT rejects them in both modes, because it cannot place a flow through an
unidentified node. The relations `wasAssociatedWith`, `wasAttributedTo` and
`actedOnBehalfOf` are accepted and ignored. For every other relation, see
[Document sections](#document-sections). Other attributes, such as `prov:time`, `prov:label` and
`adprov:content_hash`, are kept on the graph and ignored by the detector.

## The decision

`f_flow(G)` is true iff some `untrusted` entity reaches some `sink` activity along
the flow edges by a path that passes through no `endorser`.

## Minimal example

```json
{
  "prefix": {"adprov": "https://nickjones39.github.io/agentdojo-prov/ns#"},
  "entity": {
    "adprov:e_mail": {"adprov:integrity": "untrusted"}
  },
  "activity": {
    "adprov:a_read": {"adprov:role": "neutral"},
    "adprov:a_send": {"adprov:role": "sink"}
  },
  "wasGeneratedBy": {
    "adprov:g1": {"prov:entity": "adprov:e_mail", "prov:activity": "adprov:a_read"}
  },
  "used": {
    "adprov:u1": {"prov:activity": "adprov:a_send", "prov:entity": "adprov:e_mail"}
  }
}
```

`f_flow` is true for this document: the untrusted email reaches `send` with no
endorsement in between.
