# Local Compose

This profile starts the complete local dependency set before any AOR process:

- PostgreSQL 16 with the AOR migration
- Temporal Server and UI with the `aor` namespace
- NATS with JetStream and persistent storage
- MinIO with the private `aor-artifacts` bucket
- Open Policy Agent with the repository policy and data

All upstream images are pinned by version and multi-platform manifest digest. Host ports bind to `127.0.0.1`; this profile is for development and test only.

This profile requires the Docker Compose plugin with `--wait` and `--wait-timeout` support; legacy `docker-compose` v1 is not supported. Docker bridge networking also requires IPv4 forwarding on Linux. The Docker host must report `net.ipv4.ip_forward = 1`; enabling it is a host-administration step and is intentionally not performed by this repository. Trusted local AOR image builds use host networking while downloading Go modules, while every runtime container remains on the isolated Compose bridge network.

## Secrets

Create the ignored secret files before the first start:

```bash
mkdir -p deploy/compose/secrets
chmod 700 deploy/compose/secrets
umask 077
openssl rand -hex 32 > deploy/compose/secrets/postgres_password
openssl rand -hex 16 > deploy/compose/secrets/minio_root_user
openssl rand -hex 32 > deploy/compose/secrets/minio_root_password
```

The secret values are mounted as files. They are not committed or placed in AOR container environment variables.

## Start

From the repository root:

```bash
make compose-up
```

The target performs these stages in order:

1. Validate the Compose model and required secret files.
2. Pull all dependency images.
3. Start dependencies and wait for their health checks and initialization jobs.
4. Build the four AOR images serially from the current source.
5. Start AOR and wait for every process readiness endpoint.

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

The AOR HTTP endpoints in this profile expose only process lifecycle and build identity; they do not expose the product API. Until the service transports and real dependency clients are wired, this profile supports infrastructure and lifecycle smoke tests only and must not be treated as business-readiness evidence.
