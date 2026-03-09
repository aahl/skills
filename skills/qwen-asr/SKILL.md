---
name: qwen-asr
description: Transcribe audio files using Qwen ASR (千问STT). Use when the user sends voice messages and wants them converted to text.
homepage: https://github.com/aahl/qwen-asr2api
metadata:
  {
    "openclaw":
      {
        "emoji": "🎤",
        "requires": { "bins": ["uv"] },
        "install":
          [
            {"id": "uv-brew", "kind": "brew", "formula": "uv", "bins": ["uv"], "label": "Install uv (brew)"},
            {"id": "uv-pip", "kind": "pip", "formula": "uv", "bins": ["uv"], "label": "Install uv (pip)"},
            {"id": "pip-aiohttp", "kind": "pip", "formula": "aiohttp", "label": "Install aiohttp (pip)"},
            {"id": "pip-argparse", "kind": "pip", "formula": "argparse", "label": "Install argparse (pip)"},
            {"id": "pip-gradio", "kind": "pip", "formula": "gradio_client", "label": "Install gradio (pip)"},
          ],
      },
  }
---

# Qwen ASR
Transcribe an audio file (wav/mp3/ogg...) to text using Qwen ASR. No configuration or API key required.

## Usage
```shell
uv run scripts/main.py -f audio.wav
cat audio.wav | uv run scripts/main.py > transcript.txt
```

## About
Qwen ASR is a free and open-source speech-to-text model.
It is trained on a large dataset of audio files from the web.
It is available in multiple languages.
This skill bases on the Qwen ASR Demo service (qwen-qwen3-asr-demo.ms.show).
