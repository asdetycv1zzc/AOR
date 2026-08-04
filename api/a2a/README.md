# A2A HTTP+JSON profile

The AOR agent boundary implements A2A protocol version `1.0` using the
HTTP+JSON/REST binding. Agents publish the public card at
`/.well-known/agent-card.json` (and may expose the same card below a configured
base path).

Every request carries `A2A-Version: 1.0`. `A2A-Extensions` is a comma-separated
list of extension URIs. A server rejects a request that omits an extension it
declares as required. AOR runtimes advertise `urn:aor:aop:v1` as the required
organization extension.

Core resources:

- `POST /message:send`
- `POST /message:stream` (requires `capabilities.streaming`)
- `GET /tasks/{id}`
- `POST /tasks/{id}:cancel`
- `POST /tasks/{id}:subscribe` (requires `capabilities.streaming`)
- `POST|GET /tasks/{id}/pushNotificationConfigs` and
  `GET|DELETE /tasks/{id}/pushNotificationConfigs/{configId}` (requires
  `capabilities.pushNotifications`)

Streaming responses are Server-Sent Events. Each `data` line contains exactly
one `StreamResponse` member (`task`, `message`, `statusUpdate`, or
`artifactUpdate`). Push webhooks receive the same JSON object with
`Content-Type: application/a2a+json`; configured authentication credentials are
never returned by the configuration read APIs.

The pinned object schema is
`a2a-http-json.v1.schema.json`. Agent-card signatures use an RFC 8785
canonical card payload and a detached JWS signing input.
