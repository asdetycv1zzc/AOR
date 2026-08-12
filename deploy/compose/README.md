# Local Compose

This profile starts the complete local dependency set before any AOR process:

- PostgreSQL 16 with the AOR migration
- Temporal Server and UI with the `aor` namespace
- NATS with JetStream and persistent storage
- MinIO with the private `aor-artifacts` bucket
- Open Policy Agent with the repository policy and data
- Dex with a local OAuth 2.0/OIDC test issuer and rotating JWKS
- OpenTelemetry Collector with separate application and audit OTLP ingress
- A WebUI-managed catalog for OpenAI, DeepSeek, Claude, and Grok
- The classroom TEST execution and audit path in the Worker container

All upstream images are pinned by version and multi-platform manifest digest. Every container uses the host network stack; services bind their distinct ports directly to `127.0.0.1` where the image supports an explicit bind address. This profile is for development and test only.

The local Collector applies the repository redaction and mandatory trace-sampling policies, then writes basic signal summaries to its container log. This keeps Compose self-contained without pretending to provide a durable or queryable observability backend; production deployments use `observability/otel-collector.yaml` with four independently configured exporter endpoints.

This profile requires the Docker Compose plugin with `--wait` and `--wait-timeout` support; legacy `docker-compose` v1 is not supported. Every runtime and dependency container uses `network_mode: host`; internal addresses use `127.0.0.1`, and AOR binds ports 8090 through 8094 on loopback. Model-provider access therefore does not require Docker bridge forwarding.

## Classroom TEST Isolation

The TEST profile runs the core Goal -> Plan -> Execution -> Audit path inside the Worker container. The Worker has no Docker socket, and no host sandbox engine or AppArmor setup is required. Tool Broker and Worker share the host directory `${AOR_PROJECTS_HOST_PATH}` at `/var/lib/aor/repositories`; when unset it defaults to this repository's `projects/` directory. Executor branches and project repositories remain visible on the host, while audit checkouts stay in the Worker's disposable overlay. Integration and GlobalAudit are disabled in this profile.

## Toolchains

The Worker image contains Git but no language compiler, SDK, runtime, or build system. The AOR-wide inventory is stored below `${AOR_TOOLCHAINS_HOST_PATH:-aor-toolchains-data}` and mounted read-only at `/opt/aor/toolchains` in the API, curator, and Worker. A separate provisioner is the only AOR process with write access. GoalSpec creation lists the exact installed versions and execution reuses only the selected inventory entries; AOR never executes arbitrary binaries found elsewhere on the host `PATH`.

Each immediate child directory is one inventory ID and must contain `toolchain.json`; the directory name and manifest `id` must match. All `binDirs` and executable paths are relative to that directory, remain inside it after symlink resolution, and must exist. Directories must be readable and traversable by UID 65532, and Linux executables must retain their executable bits. See [`toolchain.example.json`](./toolchain.example.json) for the manifest shape. For example:

```text
/opt/aor/toolchains/
  go-1.26.5-linux-amd64/
    toolchain.json
    bin/go
    bin/gofmt
```

For GCC and G++, installation remains manual: install the requested exact version and its manifest in the inventory, then continue Goal negotiation. AOR does not run crosstool-ng or install GCC from an archive.

For other supported toolchains, Goal negotiation asks the user for the official HTTPS release archive URL and explicit authorization. The provisioner accepts only self-contained Linux archives for the current architecture, downloads and hashes the archive, extracts it without running installer scripts, checks its requested version, and atomically publishes the tool plus provenance manifest. Supported portable profiles are Go, Node.js, .NET SDK, JDK, Python, Rust, Perl, GHC, Free Pascal, NASM, and YASM. Source distributions and archives that depend on host installation scripts are rejected and must be installed manually. A durable queue retries transient download failures up to five attempts; after installation, the control process rescans the immutable inventory and automatically asks the Goal agent to replace `INSTALL_REQUIRED` with the new `INSTALLED` entry.

## Secrets

Generate the ignored local infrastructure secrets, then start AOR:

```bash
mkdir -p deploy/compose/secrets
chmod 700 deploy/compose/secrets
umask 077
make compose-init-secrets
make compose-aor-up
```

`compose-init-secrets` creates only local infrastructure values. No provider endpoint or credential is present in Compose or committed to Git. PostgreSQL migrations configure the least-privilege `aor_app` runtime role. The API and Model Gateway share `model_replay_key`: model replay responses and WebUI-supplied provider API keys are encrypted before they are written to PostgreSQL.

After the containers are healthy, open `/ui/`, choose **模型设置**, and enter the Base URL and API key for any provider you want to use. Each provider has its own **测试连接** button. OpenAI, DeepSeek, and Grok use OpenAI-compatible Chat Completions; Claude supports Anthropic Messages directly and can also use an OpenAI-compatible proxy. Saving takes effect on the next model call without restarting a container. Global role routes become defaults for future projects, while the new-project dialog can store a different combination on that project.

## Knowledge Root

The API and worker mount `/var/lib/aor/knowledge` as read-only. By default Compose uses the named `aor-knowledge-data` volume, initialized with the global namespace from the image; set `AOR_KNOWLEDGE_HOST_PATH` to an absolute host directory to serve a curated snapshot tree from another location. The API sets `AOR_KNOWLEDGE_CURATOR_URL=http://127.0.0.1:8094`, so authenticated knowledge-update requests are forwarded to the separate process that owns the only read-write knowledge mount. The curator runs the `KNOWLEDGE_CURATOR` server mode, exposes only the draft, lookup, and approval routes on `127.0.0.1:8094`, and does not start control-plane schedulers or maintenance workers. An empty root is valid, but knowledge searches and manifest reads return not found until a revision is published.

## Start

From the repository root, the complete deployment is one command:

```bash
make compose-up
```

The target performs these stages in order:

1. Generate local infrastructure secrets and validate the Compose model.
2. Pull the pinned dependency images.
3. Start PostgreSQL, Temporal, NATS, MinIO, OPA, Dex, and OpenTelemetry Collector, then wait for their health checks and initialization jobs.
4. Apply the PostgreSQL migrations and run the idempotent initialization jobs.
5. Build the AOR server image (shared by the API and curator), Model Gateway, Tool Broker, and Worker from the current source.
6. Start AOR only after every dependency and initializer has completed successfully, then wait for every process readiness endpoint.

Individual stages are available as `make compose-pull`, `make compose-deps-up`, `make compose-aor-up`, and `make compose-ps`.

### LAN access on this test host

The LAN override exposes only the WebUI/API. The TEST profile uses the configured local tenant directly, so the console opens without a login step. Start or refresh it with:

```bash
docker compose --parallel 1 \
  -f deploy/compose/docker-compose.yml \
  -f deploy/compose/docker-compose.lan.yml \
  --profile aor up -d --no-build
```

Open `http://192.168.1.193:8090/ui/` from another machine on the same network. Internal AOR, identity, and dependency ports remain bound to loopback.

## Local Endpoints

| Component | Endpoint |
|---|---|
| AOR WebUI | `http://127.0.0.1:8090/ui/` |
| AOR API lifecycle | `http://127.0.0.1:8090/health/ready` |
| AOR Curator lifecycle and approved writer API | `http://127.0.0.1:8094/health/ready` |
| Model Gateway lifecycle | `http://127.0.0.1:8091/health/ready` |
| Tool Broker lifecycle | `http://127.0.0.1:8092/health/ready` |
| Worker lifecycle | `http://127.0.0.1:8093/health/ready` |
| Temporal UI | `http://127.0.0.1:8080` |
| NATS monitoring | `http://127.0.0.1:8222` |
| MinIO API | `http://127.0.0.1:9000` |
| MinIO console | `http://127.0.0.1:9001` |
| OPA | `http://127.0.0.1:8181` |
| OIDC discovery | `http://127.0.0.1:5556/dex/.well-known/openid-configuration` |
| OpenTelemetry health | `http://127.0.0.1:13133` |
| Application OTLP | `grpc://127.0.0.1:4317`, `http://127.0.0.1:4318` |
| Audit OTLP | `grpc://127.0.0.1:4327`, `http://127.0.0.1:4328` |

## Test Identity

Dex exposes the public client `aor-control-plane`, the confidential `aor-server` workload client, and the local `mockCallback` connector. Obtain a user access token through the OAuth 2.0 Authorization Code flow with PKCE using the issuer above and the registered redirect URI `http://127.0.0.1:5555/callback`. Send the resulting token as `Authorization: Bearer <token>` to AOR HTTP APIs. The API exchanges its file-backed client credential for a five-minute token with the exact `aor-control-plane` audience before calling Model Gateway. The API, Model Gateway, and Tool Broker verify RS256 signatures against Dex JWKS, bind the exact issuer and audience, and refresh unknown signing keys for rotation.

The mock connector, default user claims, and exact `aor-server` subject mapping exist only for this test profile. Dex deterministically encodes that client ID as subject `Cgphb3Itc2VydmVy`; Model Gateway maps only that verified subject to `SERVICE` and has no default user mapping. The API and worker both use that test workload client when calling Model Gateway. The pinned Dex image is an immutable build of upstream revision `155557bd65e0cb56d38c0ef84cda17d341ada061`; v2.45.1 does not implement `client_credentials`. Runtime configuration rejects fallback claim mappings outside development or test, and production identity endpoints must use HTTPS. Replace this test issuer with the deployment's approved workload identity provider and issue explicit `tenantId`, `principalType`, and `role` claims before any production use.

The Control API exposes authenticated project creation, project reads, state reads, task reads, project commands, and project event streaming in addition to lifecycle endpoints. Every mutation is authorized by OPA again at the Orchestrator commit boundary. Other product transports must pass their own readiness and conformance gates before this profile can be treated as complete business-readiness evidence.
