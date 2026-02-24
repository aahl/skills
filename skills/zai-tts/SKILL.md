---
name: zai-tts
description: Text-to-speech conversion using GLM-TTS service via the `uvx zai-tts` command for generating audio from text. Use when (1) User requests audio/voice output with the "tts" trigger or keyword. (2) Content needs to be spoken rather than read (multitasking, accessibility, podcast, driving, cooking). (3) Using pre-cloned voices for speech.
homepage: https://github.com/aahl/zai-tts
metadata:
  {
    "openclaw":
      {
        "emoji": "🗣️",
        "requires": { "bins": ["uvx"], "env": ["ZAI_AUDIO_USERID", "ZAI_AUDIO_TOKEN"] },
        "primaryEnv": "ZAI_AUDIO_TOKEN",
        "install":
          [
            {
              "id": "userid",
              "kind": "input",
              "label": "User ID",
              "description": "Login `audio.z.ai` and executing `JSON.parse(localStorage['auth-storage']).state.user.userId` in the console via F12 Developer Tools",
              "secret": false,
              "envVar": "ZAI_AUDIO_USERID",
            },
            {
              "id": "token",
              "kind": "input",
              "label": "Auth Token",
              "description": "Login `audio.z.ai` and executing `JSON.parse(localStorage['auth-storage']).state.token` in the console via F12 Developer Tools",
              "secret": true,
              "envVar": "ZAI_AUDIO_TOKEN",
            },
            {
              "id": "uv-brew",
              "kind": "brew",
              "formula": "uv",
              "bins": ["uvx"],
              "label": "Install uvx (brew)",
            },
            {
              "id": "uv-pip",
              "kind": "pip",
              "formula": "uv",
              "bins": ["uvx"],
              "label": "Install uvx (pip)",
            },
          ],
      },
  }
---

# Zai-TTS

Generate high-quality text-to-speech audio using GLM-TTS service via the `uvx zai-tts` command.
Before using this skill, you need to configure the environment variables `ZAI_AUDIO_USERID` and `ZAI_AUDIO_TOKEN`,
which can be obtained by login `audio.z.ai` and executing `localStorage['auth-storage']` in the console via F12 Developer Tools.

## Usage
```shell
uvx zai-tts -t "{msg}" -o {tempdir}/{filename}.wav
```

## Changing speed, volume
```shell
uvx zai-tts -t "{msg}" -o {tempdir}/{filename}.wav --speed 1.5
uvx zai-tts -t "{msg}" -o {tempdir}/{filename}.wav --speed 1.5 --volume 2
```

## Changing the voice
```shell
uvx zai-tts -t "{msg}" -o {tempdir}/{filename}.wav --voice system_002
```

## Available voices
`system_001`: Lila.  A cheerful, standard-pronunciation female voice
`system_002`: Chloe. A gentle, elegant, intelligent female voice
`system_003`: Ethan. A sunny, standard-pronunciation male voice

Retrieve all available voices using shell commands:
```shell
uvx zai-tts -l
```
If you want to use custom voices, please complete voice cloning on the website `audio.z.ai` first.
