# Design

Candidates are sorted by immutable commit identity. The integration audit rejects overlapping owned paths, duplicate public interfaces, missing evidence, and non-passing module audits before invoking `MergeExecutor`. Successful merge results are stored once by tenant and IntegrationTask.
