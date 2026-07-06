# Access Control Model

Polyphemus enforces **RBAC (group membership) + ABAC (clearance & department
attributes)**, evaluated **fail-closed** and **filtered at query time**.

## Metadata schema (per chunk, mirrored from the document)

| Field | Type | Purpose |
|---|---|---|
| `allowed_groups` | `list[str]` | RBAC — which IdP groups may read the chunk |
| `classification` | enum | ABAC — sensitivity tier |
| `department` | `str` | ABAC — owning department (context/signal) |
| `source_uri` | `str` | provenance for audit and citation |

Classification order (ascending):
`public < internal < {hr_confidential, finance_confidential}`

The two confidential tiers are **siblings** at the same rank. Separation between
finance and HR is enforced by **group intersection**, not by a scalar — a finance
user and an HR user may both hold "confidential" clearance yet still cannot read
each other's departments.

`CLASSIFICATION_RANK` (in `models.py`):

```
public = 0, internal = 1, hr_confidential = 2, finance_confidential = 2
```

## Claim → attribute mapping

| IdP claim (Cognito / Entra) | `UserContext` field | Used by |
|---|---|---|
| `cognito:groups` / `groups` / `roles` | `groups` | RBAC group intersection |
| `custom:department` / `department` | `department` | ABAC department signal |
| `custom:clearance` / `clearance` | `clearance` | ABAC clearance rank |
| `sub` / `oid` | `subject` | audit identity |

Mapping is done in `authz/identity.py`. An unknown/absent clearance falls back to
`public` (fail-closed).

## Enforcement — two independent layers

### Layer 1 — Filter at query time (primary)

`authz/query_filter.build_filter(user)` emits an OpenSearch-style bool filter:

```json
{
  "bool": {
    "filter": [
      {"terms": {"allowed_groups": ["finance"]}},
      {"range": {"classification_rank": {"lte": 2}}}
    ]
  }
}
```

The vector store applies this filter **before ranking**, so unauthorized chunks
are never scored or returned. This is the primary control.

### Layer 2 — Post-retrieval re-check (defense in depth)

`authz/policy.evaluate(user, chunk)` runs on every returned chunk inside
`retrieval/retriever.py`. Rules, in order (fail-closed):

1. `deny_no_group` — empty intersection of user groups and `allowed_groups` → **deny**.
2. `clearance_lt` — `rank(chunk.classification) > rank(user.clearance)` → **deny**.
3. otherwise **allow** via `group_intersection` (department match noted as ABAC context).

Anything that slips past Layer 1 (e.g. a misconfigured index filter) is dropped
here and its `source_uri` recorded in `denied_sources`. This proves enforcement
does not depend solely on the index configuration.

## Worked example (Scenario 2)

An HR user (`groups=["hr"]`, `clearance=hr_confidential`) asks a finance question:

- Layer 1 filter excludes all `allowed_groups=["finance","admin"]` chunks →
  zero finance chunks returned.
- The model receives no authorized finance context → answers
  *"I don't have authorized information to answer that."*
- The audit record lists the finance `source_uri`s under `denied_sources`,
  proving the denial.

## Allow/deny matrix (from `tests/test_authz_policy.py`)

| User \ Resource | finance_confidential | hr_confidential | internal |
|---|:---:|:---:|:---:|
| finance_user | allow | **deny** | allow |
| hr_user | **deny** | allow | allow |
| staff_user | **deny** | **deny** | allow |
| admin | allow | allow | allow |
