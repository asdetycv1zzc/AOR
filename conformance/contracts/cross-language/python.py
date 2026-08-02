import json
from pathlib import Path


path = Path("conformance/aop/valid/goal.json")
envelope = json.loads(path.read_text(encoding="utf-8"))

if envelope["aopVersion"] != "1.0" or envelope["intent"] != "PROPOSE_GOAL":
    raise RuntimeError("Python AOP decode changed protocol meaning")
if not envelope["goalSpec"]["sha256"].startswith("sha256:"):
    raise RuntimeError("Python AOP decode lost immutable references")

round_trip = json.loads(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")))
if round_trip["messageId"] != envelope["messageId"]:
    raise RuntimeError("Python AOP round trip changed identity")
