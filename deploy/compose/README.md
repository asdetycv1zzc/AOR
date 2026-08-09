# Local Compose

This profile starts the complete local dependency set before any AOR process:

- PostgreSQL 16 with the AOR migration
- Temporal Server and UI with the `aor` namespace
- NATS with JetStream and persistent storage
- MinIO with the private `aor-artifacts` bucket
- Open Policy Agent with the repository policy and data
- Dex with a local OAuth 2.0/OIDC test issuer and rotating JWKS
- OpenTelemetry Collector with separate application and audit OTLP ingress
- Two independently configured model-provider families for the Model Gateway
- The classroom TEST execution and audit path in the Worker container

All upstream images are pinned by version and multi-platform manifest digest. Every container uses the host network stack; services bind their distinct ports directly to `127.0.0.1` where the image supports an explicit bind address. This profile is for development and test only.

The local Collector applies the repository redaction and mandatory trace-sampling policies, then writes basic signal summaries to its container log. This keeps Compose self-contained without pretending to provide a durable or queryable observability backend; production deployments use `observability/otel-collector.yaml` with four independently configured exporter endpoints.

This profile requires the Docker Compose plugin with `--wait` and `--wait-timeout` support; legacy `docker-compose` v1 is not supported. Every runtime and dependency container uses `network_mode: host`; internal addresses use `127.0.0.1`, and AOR binds ports 8090 through 8094 on loopback. Model-provider access therefore does not require Docker bridge forwarding.

## Classroom TEST Isolation

The TEST profile runs the core Goal -> Plan -> Execution -> Audit path inside the Worker container. The Worker has no Docker socket, and no host sandbox engine or AppArmor setup is required. Tool Broker and Worker share the host directory `${AOR_PROJECTS_HOST_PATH}` at `/var/lib/aor/repositories`; when unset it defaults to this repository's `projects/` directory. Executor branches and project repositories remain visible on the host, while audit checkouts and Go build caches stay in the Worker's disposable overlay. Integration and GlobalAudit are disabled in this profile.

## Secrets

Generate the ignored local infrastructure secrets. This is sufficient to start
the dependency stage; model-provider credentials are checked only before AOR is
built and started:

```bash
mkdir -p deploy/compose/secrets
chmod 700 deploy/compose/secrets
umask 077
make compose-init-secrets
make compose-deps-up

# Write actual credentials issued by each provider, one value per file.
# Do not generate placeholders: Compose checks that both files are nonempty.
${EDITOR:-vi} deploy/compose/secrets/model_provider_openai_key
${EDITOR:-vi} deploy/compose/secrets/model_provider_deepseek_key
chmod 0444 deploy/compose/secrets/model_provider_openai_key deploy/compose/secrets/model_provider_deepseek_key
make compose-aor-up
```

`compose-init-secrets` creates only local infrastructure values; it never creates or changes provider credentials. The local Compose engine exposes file-backed secrets as read-only bind mounts, so the source files use mode `0444` for the containers' distinct non-root UIDs; the containing `secrets/` directory remains mode `0700` and prevents other host users from traversing to them. The secret values are not committed or placed in AOR container environment variables. PostgreSQL migrations use the admin-only `postgres_password` to apply schema changes and configure the least-privilege `aor_app` runtime role; API, Model Gateway, Tool Broker, and worker use `secret://postgres_app_password`. AOR refers to mounted files only through `secret://` references. API, Tool Broker, and worker use the MinIO root access and secret files for local S3 access; the Model Gateway uses one mounted file for each provider family and the independent `model_replay_key` to encrypt bounded idempotency responses at rest. The Tool Broker and worker use the independent `lease_signing_key` for persistent capability leases. Dex, the API, and the worker share `aor_server_oauth_client_secret` through separate read-only mounts; the value is never placed in an AOR container environment variable.

The bundled provider catalog contains OpenAI `gpt-5.6-sol` and DeepSeek `deepseek-v4-flash` examples through OpenAI-compatible endpoints, but the control plane is not limited to those provider IDs or model names. Extend `x-model-providers` and mount the referenced credential when adding another compatible provider. The WebUI exposes only registered provider IDs, models, and capabilities; endpoints and credentials remain deployment-only configuration. Goal proposer, challenger, module planner, knowledge curator, and Executor default to the OpenAI entry; Plan Supervisor and both Auditor roles default to the DeepSeek entry. The global WebUI setting changes the defaults for future projects, while project creation stores its selected role-to-model combination as an immutable project snapshot. Set `AOR_OPENAI_BASE_URL`, `AOR_OPENAI_MODEL`, `AOR_OPENAI_REASONING_EFFORT`, `AOR_DEEPSEEK_BASE_URL`, or `AOR_DEEPSEEK_MODEL` before `make compose-up` to change the bundled entries. The test profile accepts only `PUBLIC` project data because provider residency and retention remain provider-defined; a deployment must supply verified provider metadata before allowing a higher classification.

## Knowledge Root

The API and worker mount `/var/lib/aor/knowledge` as read-only. By default Compose uses the named `aor-knowledge-data` volume, initialized with the global namespace from the image; set `AOR_KNOWLEDGE_HOST_PATH` to an absolute host directory to serve a curated snapshot tree from another location. The API sets `AOR_KNOWLEDGE_CURATOR_URL=http://127.0.0.1:8094`, so authenticated knowledge-update requests are forwarded to the separate process that owns the only read-write knowledge mount. The curator runs the `KNOWLEDGE_CURATOR` server mode, exposes only the draft, lookup, and approval routes on `127.0.0.1:8094`, and does not start control-plane schedulers or maintenance workers. An empty root is valid, but knowledge searches and manifest reads return not found until a revision is published.

## Start

From the repository root, the complete deployment remains one command when both
provider credentials are already present:

```bash
make compose-up
```

The target performs these stages in order:

1. Generate local infrastructure secrets and validate the Compose model.
2. Pull the pinned dependency images.
3. Start PostgreSQL, Temporal, NATS, MinIO, OPA, Dex, and OpenTelemetry Collector, then wait for their health checks and initialization jobs.
4. Apply the PostgreSQL migrations and run the idempotent initialization jobs.
5. Check both model-provider credentials, then build the AOR server image (shared by the API and curator), Model Gateway, Tool Broker, and Worker from the current source.
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
