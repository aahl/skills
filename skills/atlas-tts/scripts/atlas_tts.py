#!/usr/bin/env python3
"""Generate speech with Atlas Cloud's asynchronous audio API."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_API_BASE = "https://api.atlascloud.ai/api/v1"
DEFAULT_MODEL = "xai/tts-v1"
TERMINAL_FAILURES = {"failed", "canceled", "cancelled", "timeout"}


class AtlasTTSError(RuntimeError):
    """Raised when Atlas TTS generation cannot complete safely."""


def _is_loopback(hostname: str | None) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1"}


def _validate_url(url: str, *, allow_loopback_http: bool = False) -> str:
    parsed = urlparse(url)
    valid_http = (
        allow_loopback_http
        and parsed.scheme == "http"
        and _is_loopback(parsed.hostname)
    )
    if parsed.scheme != "https" and not valid_http:
        raise AtlasTTSError("Refusing a non-HTTPS URL")
    if not parsed.hostname or parsed.username or parsed.password:
        raise AtlasTTSError("Refusing an invalid or credential-bearing URL")
    return url


def _validate_api_base(url: str, *, allow_loopback_http: bool = False) -> str:
    validated = _validate_url(url, allow_loopback_http=allow_loopback_http)
    parsed = urlparse(validated)
    hostname = parsed.hostname
    if hostname != "api.atlascloud.ai" and not (
        allow_loopback_http and _is_loopback(hostname)
    ):
        raise AtlasTTSError("Refusing to send the API key to an untrusted host")
    if hostname == "api.atlascloud.ai" and (
        parsed.path.rstrip("/") != "/api/v1" or parsed.query or parsed.fragment
    ):
        raise AtlasTTSError("Atlas media API base must end with /api/v1")
    return validated


def _json_request(
    url: str,
    api_key: str,
    payload: dict[str, Any] | None = None,
    *,
    attempts: int = 1,
) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=data,
        method="GET" if payload is None else "POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "aahl-atlas-tts/1.0",
        },
    )
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=60) as response:
                result = json.load(response)
            break
        except HTTPError as error:
            transient = error.code in {404, 408, 409, 425, 429, 500, 502, 503, 504}
            if payload is None and transient and attempt + 1 < attempts:
                time.sleep(min(2**attempt, 4))
                continue
            raise AtlasTTSError(f"Atlas API returned HTTP {error.code}") from error
        except (URLError, TimeoutError) as error:
            if payload is None and attempt + 1 < attempts:
                time.sleep(min(2**attempt, 4))
                continue
            raise AtlasTTSError(
                f"Atlas API request failed: {error.reason if isinstance(error, URLError) else error}"
            ) from error
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise AtlasTTSError(
                "Atlas API returned an invalid JSON response"
            ) from error

    if not isinstance(result, dict):
        raise AtlasTTSError("Atlas API returned an unexpected response")
    if result.get("code") not in (None, 0, 200):
        raise AtlasTTSError(str(result.get("message") or "Atlas API request failed"))
    return result


def _prediction_data(response: dict[str, Any]) -> dict[str, Any]:
    data = response.get("data", response)
    if not isinstance(data, dict):
        raise AtlasTTSError("Atlas API response is missing prediction data")
    return data


def _download(url: str, output: Path, *, allow_loopback_http: bool = False) -> None:
    _validate_url(url, allow_loopback_http=allow_loopback_http)
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(f".{output.name}.part")
    request = Request(url, headers={"User-Agent": "aahl-atlas-tts/1.0"})
    try:
        with (
            urlopen(request, timeout=120) as response,
            partial.open("wb") as destination,
        ):
            while chunk := response.read(1024 * 1024):
                destination.write(chunk)
        if partial.stat().st_size == 0:
            raise AtlasTTSError("Atlas output download was empty")
        partial.replace(output)
    except (HTTPError, URLError, TimeoutError, OSError, AtlasTTSError) as error:
        partial.unlink(missing_ok=True)
        if isinstance(error, AtlasTTSError):
            raise
        raise AtlasTTSError(f"Atlas output download failed: {error}") from error


def generate(args: argparse.Namespace) -> Path:
    api_key = os.environ.get("ATLASCLOUD_API_KEY", "").strip()
    if not api_key:
        raise AtlasTTSError("ATLASCLOUD_API_KEY is not set")

    api_base = _validate_api_base(
        args.api_base.rstrip("/"), allow_loopback_http=args.allow_loopback_http
    )
    payload: dict[str, Any] = {
        "model": args.model,
        "text": args.text,
        "language": args.language,
        "voice_id": args.voice,
        "codec": args.codec,
        "speed": args.speed,
    }
    if args.sample_rate is not None:
        payload["sample_rate"] = args.sample_rate
    if args.bit_rate is not None:
        payload["bit_rate"] = args.bit_rate

    # Generation POST is intentionally issued exactly once.
    prediction = _prediction_data(
        _json_request(f"{api_base}/model/generateAudio", api_key, payload)
    )
    prediction_id = prediction.get("id")
    if not isinstance(prediction_id, str) or not prediction_id:
        raise AtlasTTSError("Atlas API did not return a prediction ID")

    delay = args.poll_interval
    for attempt in range(args.max_polls):
        if attempt:
            time.sleep(delay)
            delay = min(delay * 1.5, args.max_poll_interval)

        if attempt == 0 and prediction.get("status"):
            current = prediction
        else:
            current = _prediction_data(
                _json_request(
                    f"{api_base}/model/prediction/{prediction_id}",
                    api_key,
                    attempts=3,
                )
            )

        status = str(current.get("status", "")).lower()
        if status == "completed":
            outputs = current.get("outputs")
            if (
                not isinstance(outputs, list)
                or not outputs
                or not isinstance(outputs[0], str)
            ):
                raise AtlasTTSError(
                    "Completed prediction did not include an output URL"
                )
            output = Path(args.output).expanduser()
            _download(outputs[0], output, allow_loopback_http=args.allow_loopback_http)
            return output
        if status in TERMINAL_FAILURES:
            detail = current.get("error") or current.get("message") or status
            raise AtlasTTSError(f"Atlas prediction {status}: {detail}")

    raise AtlasTTSError(f"Atlas prediction did not finish after {args.max_polls} polls")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", help="Text to convert to speech")
    parser.add_argument("--output", required=True, help="Destination audio file")
    parser.add_argument(
        "--model", default=DEFAULT_MODEL, help="Current Atlas Cloud audio model ID"
    )
    parser.add_argument(
        "--language",
        default="auto",
        help="Language code accepted by the selected model",
    )
    parser.add_argument(
        "--voice", default="eve", help="Voice ID accepted by the selected model"
    )
    parser.add_argument(
        "--codec", choices=("mp3", "wav", "pcm", "mulaw", "alaw"), default="mp3"
    )
    parser.add_argument(
        "--sample-rate",
        type=int,
        choices=(8000, 16000, 22050, 24000, 44100, 48000),
        default=None,
    )
    parser.add_argument(
        "--bit-rate",
        type=int,
        choices=(32000, 64000, 96000, 128000, 192000),
        default=None,
    )
    parser.add_argument(
        "--speed",
        type=float,
        choices=(0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.4, 1.5),
        default=1.0,
    )
    parser.add_argument(
        "--max-polls", type=int, default=60, help="Maximum prediction checks"
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.5,
        help="Initial delay between prediction checks",
    )
    parser.add_argument(
        "--max-poll-interval", type=float, default=8.0, help="Maximum polling delay"
    )
    parser.add_argument(
        "--api-base",
        default=os.environ.get("ATLASCLOUD_MEDIA_API_BASE", DEFAULT_API_BASE),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--allow-loopback-http", action="store_true", help=argparse.SUPPRESS
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.max_polls < 1 or args.poll_interval < 0 or args.max_poll_interval < 0:
        print(
            "error: polling values must be non-negative and max-polls must be positive",
            file=sys.stderr,
        )
        return 2
    try:
        output = generate(args)
    except AtlasTTSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
