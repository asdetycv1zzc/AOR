# Local Compose

This profile starts the complete local dependency set before any AOR process:

- PostgreSQL 16 with the AOR migration
- Temporal Server and UI with the `aor` namespace
- NATS with JetStream and persistent storage
- MinIO with the private `aor-artifacts` bucket
- Open Policy Agent with the repository policy and data
- Dex with a local OAuth 2.0/OIDC test issuer and rotating JWKS
- Two independently configured model-provider families for the Model Gateway
- A pinned Linux sandbox runtime image and a rootless OCI-engine preflight

All upstream images are pinned by version and multi-platform manifest digest. Host ports bind to `127.0.0.1`; this profile is for development and test only.

This profile requires the Docker Compose plugin with `--wait` and `--wait-timeout` support; legacy `docker-compose` v1 is not supported. Docker bridge networking also requires IPv4 forwarding on Linux. The Docker host must report `net.ipv4.ip_forward = 1`; enabling it is a host-administration step and is intentionally not performed by this repository. Trusted local AOR image builds use host networking while downloading Go modules, while every runtime container remains on the isolated Compose bridge network.

## Linux Sandbox Host Prerequisites

The worker controls a dedicated rootless Docker Engine through its Unix socket. It is separate from the engine that runs the trusted Compose control-plane services. The rootful `/var/run/docker.sock` is rejected. The sandbox engine must report Linux, cgroups v2, rootless mode, the configured `runc` default runtime, CPU/memory/PID enforcement, and AppArmor or SELinux. These are host security prerequisites and this repository does not enable or simulate them.

Load the supplied AppArmor profile on the Linux host before starting Compose:

```bash
sudo install -m 0644 deploy/compose/aor-sandbox.apparmor /etc/apparmor.d/aor-sandbox
sudo apparmor_parser -r /etc/apparmor.d/aor-sandbox
```

Expose the dedicated engine socket to Compose with the numeric owner and socket group from the host. Run the Compose control plane with an engine that preserves host ownership on bind mounts:

```bash
export AOR_SANDBOX_ENGINE_SOCKET="${XDG_RUNTIME_DIR}/docker.sock"
export AOR_SANDBOX_ENGINE_UID="$(id -u)"
export AOR_SANDBOX_ENGINE_GID="$(stat -c %g "${AOR_SANDBOX_ENGINE_SOCKET}")"
```

`compose-check` fails immediately when these values are absent. `compose-deps-up` then runs `sandbox-preflight.sh`, which validates the engine before pulling the immutable runtime image into it, then creates and executes a disposable probe container using a non-root identity, read-only root filesystem, cgroups v2 limits, capability drop, `network=none`, built-in seccomp, and the `aor-sandbox` mandatory policy. Missing or downgraded host capabilities produce a specific error and prevent any AOR process from starting. The worker's access to the engine socket is a controller channel; that socket is never mounted into an Executor or Auditor container.

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
openssl rand -hex 32 > deploy/compose/secrets/aor_server_oauth_client_secret
# Exactly 32 raw bytes are required for AES-256 replay encryption.
openssl rand 32 > deploy/compose/secrets/model_replay_key
# Write the actual credentials issued by each provider, one value per file.
# Do not generate placeholder keys: Compose checks that both files are nonempty.
${EDITOR:-vi} deploy/compose/secrets/model_provider_openai_key
${EDITOR:-vi} deploy/compose/secrets/model_provider_deepseek_key
chmod 0444 deploy/compose/secrets/*
```

The local Compose engine exposes file-backed secrets as read-only bind mounts, so the source files use mode `0444` for the containers' distinct non-root UIDs; the containing `secrets/` directory remains mode `0700` and prevents other host users from traversing to them. The secret values are not committed or placed in AOR container environment variables. PostgreSQL migrations use the admin-only `postgres_password` to apply schema changes and configure the least-privilege `aor_app` runtime role; API, Model Gateway, Tool Broker, and worker use `secret://postgres_app_password`. AOR refers to mounted files only through `secret://` references. API, Tool Broker, and worker use the MinIO root access and secret files for local S3 access; the Model Gateway uses one mounted file for each provider family and the independent `model_replay_key` to encrypt bounded idempotency responses at rest. The Tool Broker uses the independent `lease_signing_key` to verify and renew persistent capability leases. Dex and the API share `aor_server_oauth_client_secret` through separate read-only mounts; the value is never placed in an AOR environment variable.

The Model Gateway defaults to OpenAI and DeepSeek OpenAI-compatible endpoints and models. Set `AOR_OPENAI_BASE_URL`, `AOR_OPENAI_MODEL`, `AOR_DEEPSEEK_BASE_URL`, or `AOR_DEEPSEEK_MODEL` in the host environment before `make compose-up` to select compatible endpoints or approved models. Provider credentials always remain in the two provider secret files.

## Knowledge Root

The API bind-mounts `knowledge/` at `/var/lib/aor/knowledge` as read-only. Set `AOR_KNOWLEDGE_HOST_PATH` to an absolute host directory to serve a curated snapshot tree from another location. Its directories and files must be readable by container UID `65532`; only the separate curator process may write them. An empty root is valid, but knowledge searches and manifest reads return not found until a revision is published.

## Start

From the repository root:

```bash
make compose-up
```

The target performs these stages in order:

1. Validate the Compose model and required secret files.
2. Pull all Compose dependency images, including the pinned Docker CLI and Linux sandbox runtime image.
3. Validate the dedicated rootless OCI engine, pull the pinned runtime into it, and execute the hardened sandbox probe.
4. Start PostgreSQL, Temporal, NATS, MinIO, OPA, and Dex, then wait for their health checks and initialization jobs.
5. Apply every PostgreSQL migration listed in `migrations/postgres/manifest.json` in order; reruns detect the installed schema, rotate the fixed `aor_app` password without revoking later grants, and keep permissions idempotent. The app password is supplied through the ignored secret file and is not printed.
6. Build the four AOR images serially from the current source. The worker image includes only the Docker CLI needed to reach the preflighted rootless engine; it does not contain or start a daemon.
7. Start AOR only after every dependency, initializer, and sandbox preflight has completed successfully, then wait for every process readiness endpoint.

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

Dex exposes the public client `aor-control-plane`, the confidential `aor-server` workload client, and the local `mockCallback` connector. Obtain a user access token through the OAuth 2.0 Authorization Code flow with PKCE using the issuer above and the registered redirect URI `http://127.0.0.1:5555/callback`. Send the resulting token as `Authorization: Bearer <token>` to AOR HTTP APIs. The API exchanges its file-backed client credential for a five-minute token with the exact `aor-control-plane` audience before calling Model Gateway. The API, Model Gateway, and Tool Broker verify RS256 signatures against Dex JWKS, bind the exact issuer and audience, and refresh unknown signing keys for rotation.

The mock connector, default user claims, and exact `aor-server` subject mapping exist only for this test profile. Dex deterministically encodes that client ID as subject `Cgphb3Itc2VydmVy`; Model Gateway maps only that verified subject to `SERVICE` and has no default user mapping. The pinned Dex image is an immutable build of upstream revision `155557bd65e0cb56d38c0ef84cda17d341ada061`; v2.45.1 does not implement `client_credentials`. Runtime configuration rejects fallback claim mappings outside development or test, and production identity endpoints must use HTTPS. Replace this test issuer with the deployment's approved workload identity provider and issue explicit `tenantId`, `principalType`, and `role` claims before any production use.

The Control API exposes authenticated project creation, project reads, state reads, task reads, project commands, and project event streaming in addition to lifecycle endpoints. Every mutation is authorized by OPA again at the Orchestrator commit boundary. Other product transports must pass their own readiness and conformance gates before this profile can be treated as complete business-readiness evidence.
