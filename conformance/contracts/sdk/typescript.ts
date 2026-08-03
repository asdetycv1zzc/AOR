import { AORClient } from "../../../sdk/typescript/aor-client.gen.ts";

let receivedURL = "";
let receivedInit: RequestInit | undefined;
const transport = async (input: string, init: RequestInit): Promise<Response> => {
  receivedURL = input;
  receivedInit = init;
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
};

const client = new AORClient("https://api.example.test/edge", transport, () => "token-1");
await client.getProject({
  pathParameters: { projectId: "project-1" },
  query: { cursor: "next" },
  headers: { "x-request-id": "request-1" },
});

if (receivedURL !== "https://api.example.test/edge/v1/projects/project-1?cursor=next") {
  throw new Error(`unexpected TypeScript SDK URL: ${receivedURL}`);
}
if (receivedInit?.method !== "GET" || (receivedInit?.headers as Headers).get("Authorization") !== "Bearer token-1") {
  throw new Error("TypeScript SDK request contract changed");
}
if ((receivedInit?.headers as Headers).get("x-request-id") !== "request-1") {
  throw new Error("TypeScript SDK custom headers were dropped");
}

let rejected = false;
try {
  new AORClient("http://api.example.test", transport);
} catch {
  rejected = true;
}
if (!rejected) throw new Error("TypeScript SDK accepted an HTTP base URL");

let missingPathRejected = false;
try {
  await client.getProject();
} catch {
  missingPathRejected = true;
}
if (!missingPathRejected) throw new Error("TypeScript SDK accepted a missing path parameter");
