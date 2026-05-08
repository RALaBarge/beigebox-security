"""JIT-generated test secrets for evals — never stored in git."""

import hashlib
import secrets
from datetime import datetime


def generate_test_secret(secret_type: str, seed: str = "") -> str:
	"""Generate deterministic fake secrets for testing (never real API keys).

	Args:
		secret_type: Type of secret (openai, anthropic, stripe, slack, etc.)
		seed: Optional seed for deterministic generation (default: timestamp)

	Returns:
		A fake secret in the correct format for that provider.
	"""
	if not seed:
		seed = f"test-{datetime.now().isoformat()}"

	# Hash the seed to get a deterministic but unpredictable value
	hash_val = hashlib.sha256(seed.encode()).hexdigest()

	match secret_type:
		case "openai":
			return f"sk-proj-{hash_val[:40]}"
		case "anthropic":
			return f"sk-ant-api03-{hash_val[:40]}"
		case "openrouter":
			return f"sk-or-v1-{hash_val[:40]}"
		case "stripe":
			return f"sk_live_{hash_val[:30]}"
		case "slack_bot":
			return f"xoxb-{hash_val[:40]}"
		case "slack_user":
			return f"xoxp-{hash_val[:40]}"
		case "github_pat":
			return f"ghp_{hash_val[:36]}"
		case "github_app":
			return f"ghs_{hash_val[:36]}"
		case "gitlab_pat":
			return f"glpat-{secrets.token_urlsafe(20)}"
		case "google_api":
			return f"AIza{secrets.token_urlsafe(30)}"
		case "aws_access":
			return f"AKIA{secrets.token_hex(16).upper()}"
		case "aws_secret":
			return secrets.token_urlsafe(40)
		case "jwt":
			# Simplified JWT format
			import base64
			header = base64.b64encode(b'{"alg":"HS256"}').decode().rstrip('=')
			payload = base64.b64encode(b'{"sub":"123"}').decode().rstrip('=')
			sig = hashlib.sha256((header + '.' + payload).encode()).hexdigest()[:43]
			return f"{header}.{payload}.{sig}"
		case "rsa_private":
			return f"-----BEGIN RSA PRIVATE KEY-----\n{hash_val}\n-----END RSA PRIVATE KEY-----"
		case _:
			raise ValueError(f"Unknown secret type: {secret_type}")


__all__ = ["generate_test_secret"]
