# Local Secrets

Files in this directory are local-only Compose secrets. Never commit their values. Compose requires all five files below before it can start AOR:

- `postgres_password`: PostgreSQL password, mounted for PostgreSQL, migrations, Temporal, API, Model Gateway, and worker. AOR uses `secret://postgres_password`.
- `minio_root_user`: local MinIO access key, mounted for MinIO initialization, API, and worker. AOR uses `secret://minio_root_user`.
- `minio_root_password`: local MinIO secret key, mounted for MinIO initialization, API, and worker. AOR uses `secret://minio_root_password`.
- `model_provider_openai_key`: issued credential for the OpenAI provider family, mounted only for the Model Gateway and referenced as `secret://model_provider_openai_key`.
- `model_provider_anthropic_key`: issued credential for the Anthropic provider family, mounted only for the Model Gateway and referenced as `secret://model_provider_anthropic_key`.

Generate the local PostgreSQL and MinIO values and write actual issued model-provider credentials with the commands in the parent `README.md`. Keep this directory mode `0700` and each file mode `0600` where supported.
