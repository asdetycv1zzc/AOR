# Local Secrets

Files in this directory are local-only Compose secrets. Never commit their values. Compose requires all eight files below before it can start AOR:

- `postgres_password`: PostgreSQL administrator password, mounted for PostgreSQL, migrations, and Temporal only.
- `postgres_app_password`: password for the non-superuser `aor_app` runtime role, mounted for API, Model Gateway, and worker. AOR uses `secret://postgres_app_password`.
- `minio_root_user`: local MinIO access key, mounted for MinIO initialization, API, and worker. AOR uses `secret://minio_root_user`.
- `minio_root_password`: local MinIO secret key, mounted for MinIO initialization, API, and worker. AOR uses `secret://minio_root_password`.
- `model_provider_openai_key`: issued credential for the OpenAI provider family, mounted only for the Model Gateway and referenced as `secret://model_provider_openai_key`.
- `model_provider_deepseek_key`: issued credential for the DeepSeek OpenAI-compatible provider family, mounted only for the Model Gateway and referenced as `secret://model_provider_deepseek_key`.
- `model_replay_key`: exactly 32 random bytes used to encrypt bounded Model Gateway idempotency responses, mounted only for the Model Gateway and referenced as `secret://model_replay_key`.
- `lease_signing_key`: 32-byte-or-longer HMAC key mounted only for the Tool Broker and referenced as `secret://lease_signing_key`.

Generate the local PostgreSQL and MinIO values and write actual issued model-provider credentials with the commands in the parent `README.md`. Keep this directory mode `0700` and each file mode `0600` where supported.
