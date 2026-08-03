# Design

Workspaces are cloned from a trusted repository into tenant/project/task/attempt directories. Git is invoked with explicit arguments and no shell. Writes reject traversal, `.git`, symlink components, forbidden paths, and paths outside the ModuleSpec allowlist. Submission performs a final lease check, verifies the clean diff is owned, commits with the service identity, and stores the manifest once.
