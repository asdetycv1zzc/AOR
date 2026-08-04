# Local Compose

This profile starts the complete local dependency set before any AOR process:

- PostgreSQL 16 with the AOR migration
- Temporal Server and UI with the `aor` namespace
- NATS with JetStream and persistent storage
- MinIO with the private `aor-artifacts` bucket
- Open Policy Agent with the repository policy and data
- Dex with a local OAuth 2.0/OIDC test issuer and rotating JWKS
- Two independently configured model-provider families for the Model Gateway

All upstream images are pinned by version and multi-platform manifest digest. Host ports bind to `127.0.0.1`; this profile is for development and test only.

This profile requires the Docker Compose plugin with `--wait` and `--wait-timeout` support; legacy `docker-compose` v1 is not supported. Docker bridge networking also requires IPv4 forwarding on Linux. The Docker host must report `net.ipv4.ip_forward = 1`; enabling it is a host-administration step and is intentionally not performed by this repository. Trusted local AOR image builds use host networking while downloading Go modules, while every runtime container remains on the isolated Compose bridge network.

## Secrets

Create the ignored secret files before the first start:

```bash
mkdir -p deploy/compose/secrets
chmod 700 deploy/compose/secrets
umask 077
openssl rand -hex 32 > deploy/compose/secrets/postgres_password
openssl rand -hex 32 > deploy/compose/secrets/postgres_app_password
openssl rand -hex 16 > deploy/compose/secrets/minio_root_user
openssl rand -hex 32 > deploy/compose/secrets/minio_root_password
openssl rand -hex 32 > deploy/compose/secrets/lease_signing_key
# Write the actual credentials issued by each provider, one value per file.
# Do not generate placeholder keys: Compose checks that both files are nonempty.
${EDITOR:-vi} deploy/compose/secrets/model_provider_openai_key
${EDITOR:-vi} deploy/compose/secrets/model_provider_deepseek_key
```

The secret values are mounted as files. They are not committed or placed in AOR container environment variables. PostgreSQL migrations use the admin-only `postgres_password` to apply schema changes and configure the least-privilege `aor_app` role; API, Model Gateway, Tool Broker, and worker use `secret://postgres_app_password`. AOR refers to mounted files only through `secret://` references. API and worker use the MinIO root access and secret files for local S3 access; the Model Gateway uses one mounted file for each provider family. The Tool Broker uses the independent `lease_signing_key` only to verify and renew persistent capability leases.

The Model Gateway defaults to OpenAI and DeepSeek OpenAI-compatible endpoints and models. Set `AOR_OPENAI_BASE_URL`, `AOR_OPENAI_MODEL`, `AOR_DEEPSEEK_BASE_URL`, or `AOR_DEEPSEEK_MODEL` in the host environment before `make compose-up` to select compatible endpoints or approved models. Provider credentials always remain in the two provider secret files.

## Start

From the repository root:

```bash
make compose-up
```

The target performs these stages in order:

1. Validate the Compose model and required secret files.
2. Pull all dependency images.
3. Start PostgreSQL, Temporal, NATS, MinIO, OPA, and Dex, then wait for their health checks and initialization jobs.
4. Apply PostgreSQL migrations `000001_core.up.sql` through `000010_outbox_tenant_discovery.up.sql` in order; reruns detect the installed schema, rotate the fixed `aor_app` password without revoking later grants, and keep permissions idempotent. The app password is supplied through the ignored secret file and is not printed.
5. Build the four AOR images serially from the current source.
6. Start AOR only after every dependency and initializer has completed successfully, then wait for every process readiness endpoint.

Individual stages are available as `make compose-pull`, `make compose-deps-up`, `make compose-aor-up`, and `make compose-ps`.

## Local Endpoints

| Component | Endpoint |
|---|---|
| AOR API lifecycle | `http://127.0.0.1:8090/health/ready` |
| Model Gateway lifecycle | `http://127.0.0.1:8091/health/ready` |
| Tool Broker lifecycle | `http://127.0.0.1:8092/health/ready` |
| Worker lifecycle | `http://127.0.0.1:8093/health/ready` |
| Temporal UI | `http://127.0.0.1:8080` |
| NATS monitoring | `http://127.0.0.1:8222` |
| MinIO API | `http://127.0.0.1:9000` |
| MinIO console | `http://127.0.0.1:9001` |
| OPA | `http://127.0.0.1:8181` |
| OIDC discovery | `http://127.0.0.1:5556/dex/.well-known/openid-configuration` |

## Test Identity

Dex exposes the public client `aor-control-plane` and the local `mockCallback` connector. Obtain an access token through the OAuth 2.0 Authorization Code flow with PKCE using the issuer above and the registered redirect URI `http://127.0.0.1:5555/callback`. Send the resulting token as `Authorization: Bearer <token>` to AOR HTTP APIs. The API, Model Gateway, and Tool Broker verify RS256 signatures against Dex JWKS, bind the exact issuer and audience, and refresh unknown signing keys for rotation.

The mock connector and `AOR_OIDC_DEFAULT_TENANT_ID`/`AOR_OIDC_DEFAULT_ROLE` mappings exist only for this test profile. Runtime configuration rejects those mappings outside development or test, and production identity endpoints must use HTTPS. Replace Dex mock identity with the deployment's approved identity provider and issue explicit `tenantId`, `principalType`, and `role` claims before any production use.

The Control API exposes authenticated project creation, project reads, state reads, task reads, project commands, and project event streaming in addition to lifecycle endpoints. Every mutation is authorized by OPA again at the Orchestrator commit boundary. Other product transports must pass their own readiness and conformance gates before this profile can be treated as complete business-readiness evidence.
