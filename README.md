# BeigeBox Security

Comprehensive security orchestration for LLM/RAG stacks.

## Overview

BeigeBox Security is a standalone microservice that provides 4 core security tools for protecting language model and retrieval-augmented generation (RAG) systems:

### 🛡️ Core Security Tools

1. **RAG Poisoning Detection** (`/v1/security/poisoning`)
   - Detects poisoned embeddings using anomaly detection
   - Methods: magnitude, centroid, neighborhood, dimension, fingerprint, hybrid
   - Per-vector confidence scoring

2. **MCP Parameter Validation** (`/v1/security/parameters`)
   - Prevents tool parameter injection attacks
   - Multi-tier validation: schema → constraint → semantic → isolation
   - Supports: WorkspaceFile, NetworkAudit, CDP, PythonInterpreter, ApexAnalyzer, and more

3. **API Anomaly Detection** (`/v1/security/anomaly`)
   - Detects token extraction and model switching attacks
   - Z-score based anomaly detection
   - Tracks: request rate, error rate, latency, payload sizes
   - Configurable sensitivity (low/medium/high)

4. **Memory Integrity Validation** (`/v1/security/memory`)
   - Detects conversation history tampering
   - HMAC-SHA256 signature verification
   - Audit logging with confidence scoring

## Quick Start

### Installation

```bash
pip install beigebox-security
```

### Running the Service

```bash
# Start server
beigebox-security server

# Check health
beigebox-security health

# View docs
beigebox-security docs
```

### Docker

```bash
# Build and run
docker-compose up -d

# Check status
curl http://localhost:8001/health
```

## API Usage

### Example: RAG Poisoning Detection

```python
import httpx

client = httpx.Client(base_url="http://localhost:8001")

# Detect poisoning in embeddings
response = client.post(
    "/v1/security/poisoning/detect",
    json={
        "embeddings": [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]],
        "method": "hybrid",
        "sensitivity": 3.0,
        "collection_id": "my_collection"
    }
)

print(response.json())
# {
#   "poisoned": [false, true],
#   "scores": [0.2, 0.8],
#   "confidence": 0.95,
#   "method_used": "hybrid"
# }
```

### Example: Parameter Validation

```python
# Validate tool parameters
response = client.post(
    "/v1/security/parameters/validate",
    json={
        "tool_name": "workspace_file",
        "parameters": {
            "path": "/home/user/docs/file.txt",
            "operation": "read"
        },
        "allow_unsafe": False
    }
)

print(response.json())
# {
#   "valid": true,
#   "issues": [],
#   "sanitized_parameters": {...}
# }
```

## Configuration

Configuration via environment variables or `.env` file:

```bash
# Server
BEIGEBOX_SECURITY_HOST=0.0.0.0
BEIGEBOX_SECURITY_PORT=8001
BEIGEBOX_SECURITY_DEBUG=false

# RAG Poisoning Detection
BEIGEBOX_SECURITY_POISONING_DETECTION_ENABLED=true
BEIGEBOX_SECURITY_POISONING_SENSITIVITY=medium
BEIGEBOX_SECURITY_POISONING_BASELINE_WINDOW=1000

# MCP Parameter Validation
BEIGEBOX_SECURITY_PARAMETER_VALIDATION_ENABLED=true
BEIGEBOX_SECURITY_PARAMETER_VALIDATION_ALLOW_UNSAFE=false

# API Anomaly Detection
BEIGEBOX_SECURITY_ANOMALY_DETECTION_ENABLED=true
BEIGEBOX_SECURITY_ANOMALY_DETECTION_SENSITIVITY=medium
BEIGEBOX_SECURITY_ANOMALY_DETECTION_DB_PATH=./data/anomaly_baselines.db

# Memory Integrity Validation
BEIGEBOX_SECURITY_MEMORY_INTEGRITY_ENABLED=true
BEIGEBOX_SECURITY_MEMORY_INTEGRITY_STRICT_MODE=false
BEIGEBOX_SECURITY_MEMORY_INTEGRITY_KEY=your-secret-key-here
```

## Integration

### With BeigeBox LLM Proxy

BeigeBox Security integrates seamlessly with the [BeigeBox](https://github.com/beigebox-ai/beigebox) LLM proxy:

```python
# In your BeigeBox config
security:
  poisoning_detection:
    enabled: true
  mcp_validator:
    enabled: true
  api_anomaly:
    enabled: true
  memory_integrity:
    enabled: true
```

### Standalone

Use as a standalone security microservice for any LLM/RAG application:

```python
import httpx

# Your application
async def protect_rag_request(embeddings):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8001/v1/security/poisoning/detect",
            json={"embeddings": embeddings}
        )
        findings = response.json()
        
        if any(findings["poisoned"]):
            # Handle poisoning
            return "BLOCKED: Suspicious embeddings detected"
        
        return "ALLOWED"
```

## API Documentation

Once running, access interactive API docs at:

- **Swagger UI:** http://localhost:8001/docs
- **ReDoc:** http://localhost:8001/redoc
- **OpenAPI Schema:** http://localhost:8001/openapi.json

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=beigebox_security

# Format code
black beigebox_security tests

# Lint
ruff check beigebox_security tests

# Type checking
mypy beigebox_security
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Licensing

Apache License 2.0 — See [LICENSE](LICENSE) for details.

## Support

- **Issues:** https://github.com/beigebox-ai/beigebox-security/issues
- **Discussions:** https://github.com/beigebox-ai/beigebox-security/discussions
- **Docs:** https://beigebox-security.readthedocs.io

## Research

BeigeBox Security is based on peer-reviewed research in LLM security:

- **RAG Poisoning:** [PoisonedRAG](https://arxiv.org/abs/2401.08788) - 97-99% attack success with 5 poisoned documents
- **OWASP Top 10 for LLMs:** [https://owasp.org/www-project-top-10-for-large-language-model-applications/](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- **Vector Database Security:** [LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/)
