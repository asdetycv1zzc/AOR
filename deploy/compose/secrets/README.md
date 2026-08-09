# Local Secrets

Files in this directory are local-only Compose secrets. Never commit their values. Compose requires these infrastructure secrets before it can start AOR:

- `postgres_password`: PostgreSQL administrator password, mounted for PostgreSQL, migrations, and Temporal only.
- `postgres_app_password`: password for the non-superuser `aor_app` runtime role, mounted for API, Model Gateway, and worker. AOR uses `secret://postgres_app_password`.
- `minio_root_user`: local MinIO access key, mounted for MinIO initialization, API, and worker. AOR uses `secret://minio_root_user`.
- `minio_root_password`: local MinIO secret key, mounted for MinIO initialization, API, and worker. AOR uses `secret://minio_root_password`.
- `model_replay_key`: exactly 32 random bytes used to encrypt Model Gateway replay data and the provider credentials saved through the WebUI. It is mounted by the API and Model Gateway and referenced as `secret://model_replay_key`.
- `lease_signing_key`: 32-byte-or-longer HMAC key mounted only for the Tool Broker and referenced as `secret://lease_signing_key`.
- `aor_server_oauth_client_secret`: confidential OAuth client secret shared only by Dex and the API process. The API exchanges it for a five-minute workload token before calling Model Gateway.

`make compose-init-secrets` generates every value above. Provider Base URLs and API keys are entered after startup in the WebUI model settings and are stored encrypted in PostgreSQL; they are not Compose secrets. Keep this directory mode `0700`. File-backed Compose secrets use mode `0444` so each container's non-root UID can read its mounted file; the non-traversable directory protects the source files on the host.
