import importlib.util
from pathlib import Path


module_path = Path(__file__).resolve().parents[3] / "sdk" / "python" / "aor_client_gen.py"
spec = importlib.util.spec_from_file_location("aor_client_gen", module_path)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load generated Python SDK")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

received = None


def transport(request):
    global received
    received = request
    return {"status": 200}


client = module.AORClient(
    "https://api.example.test/edge",
    transport=transport,
    token_provider=lambda: "token-1",
)
client.get_project(
    {
        "path_parameters": {"projectId": "project-1"},
        "query": {"cursor": "next"},
        "headers": {"X-Request-ID": "request-1"},
    }
)

if received is None:
    raise RuntimeError("Python SDK transport was not called")
if received.get_method() != "GET" or received.full_url != "https://api.example.test/edge/v1/projects/project-1?cursor=next":
    raise RuntimeError(f"unexpected Python SDK request: {received.get_method()} {received.full_url}")
if received.headers.get("Authorization") != "Bearer token-1" or received.headers.get("X-request-id") != "request-1":
    raise RuntimeError("Python SDK request headers were not preserved")

try:
    module.AORClient("http://api.example.test", transport=transport)
except ValueError:
    pass
else:
    raise RuntimeError("Python SDK accepted an HTTP base URL")

try:
    client.get_project()
except ValueError:
    pass
else:
    raise RuntimeError("Python SDK accepted a missing path parameter")
