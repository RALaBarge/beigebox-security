"""Load evals corpora with JIT-generated test secrets."""

import re
from pathlib import Path
from typing import Any

import yaml

from beigebox.evals.security.test_secrets import generate_test_secret


def load_corpus(corpus_path: str | Path) -> list[dict[str, Any]]:
	"""Load a YAML corpus and substitute ${SECRET:type} placeholders with generated secrets.

	Args:
		corpus_path: Path to the YAML corpus file

	Returns:
		List of corpus rows with secrets substituted
	"""
	corpus_path = Path(corpus_path)
	with open(corpus_path) as f:
		data = yaml.safe_load(f)

	rows = data.get("rows", [])

	# Substitute ${SECRET:type} placeholders
	for row in rows:
		if "text" in row:
			row["text"] = _substitute_secrets(row["text"])

	return rows


def _substitute_secrets(text: str) -> str:
	"""Replace ${SECRET:type} with generated fake secrets."""

	def replacer(match):
		secret_type = match.group(1)
		# Use secret_type as seed for deterministic generation
		return generate_test_secret(secret_type, seed=f"evals-{secret_type}")

	return re.sub(r"\$\{SECRET:(\w+)\}", replacer, text)


__all__ = ["load_corpus"]
