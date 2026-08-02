# AI layer

## Grounding

Retrieval runs over platform evidence scoped to the caller tenant. The model receives only retrieved
evidence and must cite it. If retrieval yields nothing, the response is withheld and marked
`unverified` with an empty citation list. A brief is never fabricated to fill a gap.

## Correlation briefs

When evidence resolution fails or returns nothing, the brief is generated without invoking the model
at all. This is asserted by a behavior test that fails if the retrieval path is touched.

## Report generation

Report structure, metrics, and evidence tables are produced deterministically by the internal worker.
The model may assist with narrative framing only, over already-retrieved evidence. The internal report
worker never persists an LLM-written report body.

## Hard limits

- No autonomous execution, dispatch, approval, or configuration change.
- No cross-tenant retrieval, ever.
- Confidence and freshness are always displayed alongside AI output.
