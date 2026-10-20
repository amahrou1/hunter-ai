# GraphQL testing (read this first)

<!-- ===================== MANDATORY RUN CONTRACT ===================== -->
<!-- If this phase is running you MUST read this whole file and work every MUST
     step for each GraphQL endpoint found. SCOPE BOUNDARY: object-level
     authorization / BOLA against mutations is handled by a SEPARATE
     authenticated-testing effort - do NOT do per-object IDOR here. DoS / query-
     cost / alias / deep-nesting abuse is DETECTED and NOTED, never executed
     (most programs, incl. TikTok, exclude DoS). Each MUST step produces leads/
     findings via hk; a summary without the record is a FAILURE. -->

## RUN CONTRACT — complete every MUST per endpoint

- [ ] **M1 Find endpoints**: GraphQL endpoints (common paths + nuclei
      graphql-detect + the ops from 06c-jsintel's graphql-ops.txt).
      → artifact: `gql-endpoints.txt`
- [ ] **M2 Introspection**: probe `{__schema{types{name}}}`; if enabled, dump
      the schema; if disabled, recover operations from JS. → artifact: `schema.json`
      (or `operations.txt` when introspection is off).
- [ ] **M3 Surface the operations**: list queries/mutations/subscriptions and
      their argument shapes (from the schema or JS). → artifact: `operations.txt`
- [ ] **M4 GET-based CSRF**: if the endpoint accepts the query over GET
      (url-encoded), a state-changing mutation over GET with cookies is a CSRF
      lead. Record it.
- [ ] **M5 Info exposure**: field-suggestion errors leaking schema, verbose
      errors, debug/`__typename` enumeration, overly broad queries returning
      other users' fields → leads.
- [ ] **M6 DoS NOTE-ONLY**: if query-cost/alias/deep-nesting abuse looks
      possible, DESCRIBE it as a caveated lead (`provenance: unconfirmed, not
      executed - program may exclude DoS`). Do NOT run it.
- [ ] **M7 Completion gate**: ./handoff.md with the endpoints, whether
      introspection is on, the operation inventory, and the leads - and an
      explicit note that per-object authorization on mutations is deferred to the
      authenticated-testing effort. Only after M1–M6.
<!-- =================== END MANDATORY RUN CONTRACT =================== -->

## Detail

Detection: try `POST {endpoint}` with `{"query":"{__typename}"}`; a GraphQL
error shape or a `data` object confirms it. Common paths: `/graphql`,
`/api/graphql`, `/v1/graphql`, `/query`, `/gql`, `/graphiql`.

Introspection query (if enabled, dump it to schema.json):
`{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name}}}}"}`

If introspection is OFF, recover operations from JS (06c-jsintel) and from
`grep -Eo '(query|mutation|subscription) \w+\('` over the bundles.

GET-based CSRF: url-encode the JSON query and send it as
`GET {endpoint}?query=...` with the session cookie. If a MUTATION succeeds over
GET, that is CSRF (no custom header required) - record a finding-track lead.

Record each real issue with `hk finding add --kind graphql ...` (introspection
leak, GET-mutation CSRF, field-level over-exposure). Leads for the rest with
`hk add lead graphql <endpoint> --evidence "..."`. Remember: per-object authz on
mutations is NOT tested here, and DoS is never executed.
