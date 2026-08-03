# Migration Plan

Route `SUBMITTED` tasks to the pipeline before enabling LLM audit. Existing task evidence is imported only when its immutable submission and commit references validate; invalid historical evidence remains inconclusive.
