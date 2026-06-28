"""
STT tool — speech-to-text via configured voice.stt_url backend.

Input: path to an audio file (wav, mp3, flac, etc.). Calls the STT backend
(OpenAI-compatible /v1/audio/transcriptions) and returns the transcribed text.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx

from beigebox.config import get_config

logger = logging.getLogger(__name__)

_AUDIO_EXTENSIONS = {".wav", ".mp3", ".mp4", ".mpeg", ".mpga", ".m4a", ".webm", ".flac", ".ogg", ".oga", ".opus"}


class STTTool:
    description = (
        "Transcribe speech audio to text. input = path to audio file (wav/mp3/flac/etc). "
        'Example: {"tool": "stt", "input": "/workspace/recording.wav"}'
    )

    def run(self, input_text: str) -> str:
        cfg = get_config()
        voice_cfg = cfg.get("voice", {})
        stt_url = voice_cfg.get("stt_url", "").rstrip("/")
        if not stt_url:
            return "Error: STT not configured (set voice.stt_url in config.yaml)"

        path_str = input_text.strip()
        if not path_str:
            return "Error: no file path provided"

        file_path = Path(path_str)
        if not file_path.exists():
            return f"Error: file not found: {path_str}"

        suffix = file_path.suffix.lower()
        if suffix not in _AUDIO_EXTENSIONS:
            return (
                f"Error: unsupported audio format '{suffix}'. "
                f"Supported: {', '.join(sorted(_AUDIO_EXTENSIONS))}"
            )

        try:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, f"audio/{suffix.lstrip('.')}")}
                resp = httpx.post(
                    f"{stt_url}/v1/audio/transcriptions",
                    files=files,
                    data={"model": cfg.get("models", {}).get("default", "whisper-1"), "response_format": "json"},
                    timeout=120,
                )
            resp.raise_for_status()
            result = resp.json()
            text = result.get("text", "")
        except Exception as exc:
            logger.error("STT request failed: %s", exc)
            return f"Error: STT request failed: {exc}"

        logger.info("STT: transcribed %s → %d chars", path_str, len(text))
        return text if text else "[no speech detected]"
