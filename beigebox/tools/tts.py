"""
TTS tool — text-to-speech via configured voice.tts_url backend.

Expects a plain text string as input. Calls the TTS backend (OpenAI-compatible
/v1/audio/speech), saves the audio to the workspace, and returns the file path.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import httpx

from beigebox.config import get_config

logger = logging.getLogger(__name__)


class TTSTool:
    description = 'Convert text to speech audio. input = text string. Saves an mp3/wav file and returns the path. Example: {"tool": "tts", "input": "Hello world"}'

    def run(self, input_text: str) -> str:
        cfg = get_config()
        voice_cfg = cfg.get("voice", {})
        tts_url = voice_cfg.get("tts_url", "").rstrip("/")
        if not tts_url:
            return "Error: TTS not configured (set voice.tts_url in config.yaml)"

        text = input_text.strip()
        if not text:
            return "Error: no text provided"

        model = voice_cfg.get("tts_model", "kokoro")
        voice = voice_cfg.get("tts_voice", "af_bella")
        speed = float(voice_cfg.get("tts_speed", 1.0))

        body = {
            "model": model,
            "input": text,
            "voice": voice,
            "speed": speed,
        }

        try:
            resp = httpx.post(
                f"{tts_url}/v1/audio/speech",
                json=body,
                timeout=60,
            )
            resp.raise_for_status()
        except Exception as exc:
            logger.error("TTS request failed: %s", exc)
            return f"Error: TTS request failed: {exc}"

        workspace_dir = cfg.get("storage", {}).get("workspace_dir", "/tmp/beigebox_workspace")
        ws = Path(workspace_dir)
        ws.mkdir(parents=True, exist_ok=True)

        ext = ".mp3" if "mp3" in (resp.headers.get("content-type", "")) else ".wav"
        ts = int(time.time())
        out_path = ws / f"tts_{ts}{ext}"
        out_path.write_bytes(resp.content)

        logger.info("TTS: saved %d bytes to %s", len(resp.content), out_path)
        return f"Speech saved to {out_path} [{len(resp.content)} bytes, {len(text)} chars]"
