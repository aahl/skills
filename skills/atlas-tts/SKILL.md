---
name: atlas-tts
description: Generate text-to-speech audio with Atlas Cloud. Use when the user wants an audio or voice file and has an ATLASCLOUD_API_KEY. Supports language, voice, codec, sample-rate, bit-rate, and speed controls.
---

# Atlas Cloud TTS

Generate speech with Atlas Cloud's asynchronous audio API. The bundled client submits exactly one generation request, polls the prediction with bounded backoff, and downloads the result without forwarding the API key to the media host.

## Requirements

- Python 3.9 or newer
- An Atlas Cloud API key in `ATLASCLOUD_API_KEY`

```shell
export ATLASCLOUD_API_KEY="..."
```

## Generate speech

```shell
python3 skills/atlas-tts/scripts/atlas_tts.py \
  "Hello from Atlas Cloud." \
  --output /tmp/atlas-speech.mp3
```

Select a language, voice, and speaking speed:

```shell
python3 skills/atlas-tts/scripts/atlas_tts.py \
  "欢迎使用 Atlas Cloud。" \
  --language zh \
  --voice jpi39icg \
  --speed 1.1 \
  --output /tmp/atlas-speech.mp3
```

The default model is `xai/tts-v1`. Use `--model` to select another current Atlas Cloud audio model after checking its input schema. Run `--help` for all options.

## Operational behavior

- Generation is sent once and is never retried automatically because it may be billable.
- Prediction polling uses a finite attempt limit and capped backoff.
- The API credential is used only for Atlas API requests, never for the output download.
- Partial output files are removed when a download fails.
