# Interfaces

- `repository.Service.CreateWorkspace` pins a task attempt to a base commit.
- `WriteFile`, `DeleteFile`, and `ReadFile` are the only workspace file operations.
- `Submit` returns a validated `contracts.SubmissionManifest` and is idempotent per tenant/task/attempt.
- `LeaseValidator` is fail-closed and must revalidate fencing and expiry at every write or submit boundary.
