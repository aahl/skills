# /// script
# requires-python = ">=3.11"
# dependencies = ["aiohttp", "argparse", "gradio_client"]
# ///
import os
import sys
import logging
import asyncio
import aiohttp
import argparse
from gradio_client import Client, handle_file
from contextlib import contextmanager, redirect_stdout

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.INFO)
BASE_URL = "https://qwen-qwen3-asr-demo.ms.show"
USER_AGENT = "Mozilla/5.0 AppleWebKit/537.36 Chrome/143 Safari/537"
SESSION: aiohttp.ClientSession | None = None

@contextmanager
def gradio_stdout():
    with redirect_stdout(sys.stderr):
        yield

async def transcribe(file, prompt="", lang="auto", itn=False):
    audio_path = await upload_file(file)
    if not audio_path:
        exit(1)
    audio_url = f"{BASE_URL}/gradio_api/file={audio_path}"
    res = await SESSION.get(audio_url)
    if res.status == 200:
        _LOGGER.warning("Audio file: %s", audio_url)
    else:
        _LOGGER.warning("Audio file upload failed: %s", [audio_url, res.status, res.headers])
        exit(1)

    with gradio_stdout():
        gradio = Client(BASE_URL)
        result = gradio.predict(
            audio_file=handle_file(audio_url),
            context=prompt or "",
            language=lang or "auto",
            enable_itn=itn or False,
            api_name="/asr_inference",
        )
        gradio.close()
        _LOGGER.info("Gradio result: %s", result)
        return result[0]

async def upload_file(audio):
    file = None
    if isinstance(audio, (bytes, bytearray)):
        file = audio
    elif audio in (None, "", "-"):
        file = sys.stdin.buffer.read()
    elif audio:
        with open(audio, "rb") as f:
            file = f.read()
    if not file:
        _LOGGER.warning("No file provided. %s", audio[:100])
        return None
    form = aiohttp.FormData()
    form.add_field("files", file, filename="audio")
    res = await api_request("/gradio_api/upload", data=form)
    try:
        src = (await res.json())[0]
        if not src:
            _LOGGER.warning("Upload failed: %s", [res.status, await res.text()])
    except:
        src = None
        _LOGGER.error("Upload failed: %s", [res.status, await res.text()], exc_info=True)
    return src

async def api_request(api, json=None, headers=None, **kwargs):
    _LOGGER.info("%s: %s", api, json)
    return await SESSION.post(
        api,
        json=json,
        headers={
            aiohttp.hdrs.USER_AGENT: USER_AGENT,
            aiohttp.hdrs.REFERER: BASE_URL,
            **(headers or {}),
        },
        **kwargs,
    )

async def main():
    global SESSION
    async with aiohttp.ClientSession(base_url=BASE_URL) as SESSION:
        parser = argparse.ArgumentParser()
        parser.add_argument("-f", "--file", help="Audio file, - for stdio")
        parser.add_argument("-p", "--prompt", help="Context")
        parser.add_argument("--lang", help="Language: auto/zh/en/ja/ko/es/fr/de/ar/it/ru/pt")
        parser.add_argument("--itn", help="Enable ITN", action="store_true")
        args = parser.parse_args()
        if args.file in (None, ""):
            file = sys.stdin.buffer.read()
            if file:
                args.file = file
        if args.file:
            print(await transcribe(**vars(args)))
        else:
            parser.print_help()

if __name__ == "__main__":
    asyncio.run(main())
