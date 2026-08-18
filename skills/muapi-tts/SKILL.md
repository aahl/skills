---
name: muapi-tts
description: Generate text-to-speech audio with MuAPI. Use when the user wants an audio or voice file and has a MUAPI_API_KEY. Supports model, voice, format, pitch, volume, emotion, language, and output-quality controls.
---

# MuAPI TTS

Generate speech with MuAPI's asynchronous text-to-speech API. The bundled client submits
exactly one generation request, polls the prediction with bounded backoff, and downloads the
result without forwarding the API key to the media host.

## Requirements

- Python 3.9 or newer
- A MuAPI API key in `MUAPI_API_KEY`

```shell
export MUAPI_API_KEY="..."
```

## Generate speech

```shell
python3 skills/muapi-tts/scripts/muapi_tts.py \
  "Hello from MuAPI." \
  --output /tmp/muapi-speech.mp3
```

The default model is `minimax-speech-2.6-hd`. Use `--model` to select another current MuAPI
text-to-audio model after checking its input schema. Use `--voice-id`, `--emotion`, `--pitch`,
`--volume`, `--format`, or the output-quality flags for model-supported controls.

## Operational behavior

- Generation is sent once and is never retried automatically because it may be billable.
- Prediction polling uses a finite attempt limit and capped backoff.
- The API credential is used only for MuAPI requests, never for the output download.
- Partial output files are removed when a download fails.
