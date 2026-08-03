# WP-09 Execution and Repository

WP-09 owns executor workspaces and the Repository Service. It accepts only a leased Executor identity, materializes a pinned base commit, enforces ModuleSpec path ownership, and emits an immutable Submission Manifest.

It does not evaluate audit verdicts, approve goals, merge branches, or expose Git credentials to agents.
