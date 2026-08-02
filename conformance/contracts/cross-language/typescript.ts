const { readFileSync } = require("node:fs");

type SpecRef = { version: number; sha256: string };
type Envelope = {
  aopVersion: "1.0";
  messageId: string;
  idempotencyKey: string;
  projectId: string;
  goalSpec: SpecRef;
  intent: string;
  expectedAggregateVersion: number;
};

const raw = readFileSync("conformance/aop/valid/goal.json", "utf8");
const envelope = JSON.parse(raw) as Envelope;

if (envelope.aopVersion !== "1.0" || envelope.intent !== "PROPOSE_GOAL") {
  throw new Error("TypeScript AOP decode changed protocol meaning");
}
if (!envelope.goalSpec.sha256.startsWith("sha256:") || envelope.expectedAggregateVersion !== 0) {
  throw new Error("TypeScript AOP decode lost immutable references");
}

const roundTrip = JSON.parse(JSON.stringify(envelope)) as Envelope;
if (roundTrip.messageId !== envelope.messageId || roundTrip.idempotencyKey !== envelope.idempotencyKey) {
  throw new Error("TypeScript AOP round trip changed identity");
}
