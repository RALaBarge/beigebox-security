# Backend Plugins — Custom Inference Engines

Files in this directory are loaded with `importlib.exec_module` at startup
and run **in-process** with full Python privileges. They are BeigeBox code,
just discovered at startup rather than statically imported.

## Trust model

- **Plugins are operator-trusted.** You vouch for every file on the
  `backend_plugins.allowed` list in `config.yaml`. The loader does not
  sandbox them.
- **Allow-list gated.** A `.py` file in this directory is only loaded if
  its stem (filename without `.py`) is in `backend_plugins.allowed`.
  Without that list, the loader logs a deprecation warning and loads
  everything (one release of grace, then it'll refuse).
- **Filesystem-perms gated.** The loader refuses to scan this directory if
  it's world-writable (`o+w`). Keep it owned by the BeigeBox process user
  with mode 750 or stricter.
- **Third-party plugin loading is not a supported flow.** Community plugins
  get vendored, code-reviewed, and added to the allow-list explicitly. See
  `BEIGEBOX_IS_NOT.md` § "Plugin model".

## Adding a plugin

1. Drop a `.py` file in this directory with a `BaseBackend` subclass.
2. Add the file's stem to `backend_plugins.allowed` in `config.yaml`.
3. Reference the backend in `backends:` by `provider: <snake_case>` where
   `<snake_case>` is the class name minus `Backend`, snake-cased.
4. Restart BeigeBox.

## Plugin contract

```python
# backends/plugins/llama_cpp.py
from beigebox.backends.base import BaseBackend, BackendResponse
import httpx

class LlamaCppBackend(BaseBackend):
    """llama.cpp HTTP server integration."""

    async def forward(self, body: dict) -> BackendResponse:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.url}/v1/chat/completions",
                json=body,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return BackendResponse(
                ok=True,
                data=resp.json(),
                backend_name=self.name,
            )

    async def forward_stream(self, body: dict):
        async with httpx.AsyncClient() as client:
            async with client.stream("POST", f"{self.url}/v1/chat/completions", json=body) as resp:
                async for line in resp.aiter_lines():
                    if line:
                        yield line

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.url}/health")
                return resp.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.url}/v1/models")
                return [m["id"] for m in resp.json().get("data", [])]
        except Exception:
            return []
```

## Required methods on `BaseBackend`

| Method | Purpose |
|---|---|
| `async forward(body) -> BackendResponse` | Non-streaming chat completion. |
| `async forward_stream(body)` | Streaming chat completion (yields SSE lines). |
| `async health_check() -> bool` | Reachability probe. Called periodically by the router. |
| `async list_models() -> list[str]` | Model catalog. Store in `self._available_models` so the router's `supports_model()` works. |

## Config example

```yaml
# config.yaml

backend_plugins:
  allowed:
    - llama_cpp           # ← stem of llama_cpp.py
    - executorch
    - mini_sglang

backends:
  - provider: llama_cpp   # ← snake_case of LlamaCppBackend (minus "Backend")
    name: llama-local
    url: http://localhost:9000
    priority: 3
```

## Shared model path

All in-tree backend integrations share the model path configured in
`config.yaml` under `backend.models_path`. Drop your model files there and
all engines see them:

```yaml
backend:
  models_path: "/mnt/storage/models"
```

## Included examples

- `llama_cpp.py` — llama.cpp HTTP server integration.
- `executorch.py` — Meta's embedded engine.
- `mini_sglang.py` — readable serving framework.

## Router behaviour

The router tracks per-backend latency (P95) and:

- Deprioritizes slow backends via `latency_p95_threshold_ms`.
- Fails over to the next-priority backend on error.
- Splits traffic across backends via `traffic_split` weights.

Your backend just needs to return correct `BackendResponse` values; the
router handles the rest.

## Tips

- **Test the upstream first.** Make sure the engine returns
  OpenAI-compatible JSON before wiring up the plugin.
- **Catch exceptions.** Always return `BackendResponse(ok=False, error=…)`
  on failure rather than letting an exception bubble.
- **Respect `self.timeout`.** It's read from config per-backend.
- **Use `logger.error/warning()` for diagnostics.** No `print` statements.
