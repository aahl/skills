#!/usr/bin/env python3
"""Generate speech with MuAPI's asynchronous text-to-speech API."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

DEFAULT_API_BASE = "https://api.muapi.ai/api/v1"
DEFAULT_MODEL = "minimax-speech-2.6-hd"
TERMINAL_FAILURES = {"failed", "canceled", "cancelled", "timeout"}


class MuAPITTSError(RuntimeError):
    """Raised when MuAPI TTS generation cannot complete safely."""


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
        raise MuAPITTSError("Refusing a non-HTTPS URL")
    if not parsed.hostname or parsed.username or parsed.password:
        raise MuAPITTSError("Refusing an invalid or credential-bearing URL")
    return url


def _validate_api_base(url: str, *, allow_loopback_http: bool = False) -> str:
    validated = _validate_url(url, allow_loopback_http=allow_loopback_http)
    parsed = urlparse(validated)
    hostname = parsed.hostname
    if hostname != "api.muapi.ai" and not (
        allow_loopback_http and _is_loopback(hostname)
    ):
        raise MuAPITTSError("Refusing to send the API key to an untrusted host")
    if hostname == "api.muapi.ai" and (
        parsed.path.rstrip("/") != "/api/v1" or parsed.query or parsed.fragment
    ):
        raise MuAPITTSError("MuAPI media API base must end with /api/v1")
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
            "x-api-key": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "aahl-muapi-tts/1.0",
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
            raise MuAPITTSError(f"MuAPI returned HTTP {error.code}") from error
        except (URLError, TimeoutError) as error:
            if payload is None and attempt + 1 < attempts:
                time.sleep(min(2**attempt, 4))
                continue
            reason = error.reason if isinstance(error, URLError) else error
            raise MuAPITTSError(f"MuAPI request failed: {reason}") from error
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise MuAPITTSError("MuAPI returned an invalid JSON response") from error

    if not isinstance(result, dict):
        raise MuAPITTSError("MuAPI returned an unexpected response")
    if result.get("error"):
        raise MuAPITTSError(str(result["error"]))
    return result


def _response_data(response: dict[str, Any]) -> dict[str, Any]:
    data = response.get("data", response)
    if not isinstance(data, dict):
        raise MuAPITTSError("MuAPI response is missing prediction data")
    return data


def _prediction_id(response: dict[str, Any]) -> str:
    data = _response_data(response)
    for key in ("request_id", "id"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    raise MuAPITTSError("MuAPI did not return a prediction ID")


def _output_url(response: dict[str, Any]) -> str:
    data = _response_data(response)
    outputs = data.get("outputs")
    if isinstance(outputs, list) and outputs and isinstance(outputs[0], str):
        return outputs[0]
    output = data.get("output")
    if isinstance(output, str) and output:
        return output
    raise MuAPITTSError("Completed prediction did not include an output URL")


def _download(url: str, output: Path, *, allow_loopback_http: bool = False) -> None:
    _validate_url(url, allow_loopback_http=allow_loopback_http)
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(f".{output.name}.part")
    request = Request(url, headers={"User-Agent": "aahl-muapi-tts/1.0"})
    try:
        with (
            urlopen(request, timeout=120) as response,
            partial.open("wb") as destination,
        ):
            while chunk := response.read(1024 * 1024):
                destination.write(chunk)
        if partial.stat().st_size == 0:
            raise MuAPITTSError("MuAPI output download was empty")
        partial.replace(output)
    except (HTTPError, URLError, TimeoutError, OSError, MuAPITTSError) as error:
        partial.unlink(missing_ok=True)
        if isinstance(error, MuAPITTSError):
            raise
        raise MuAPITTSError(f"MuAPI output download failed: {error}") from error


def generate(args: argparse.Namespace) -> Path:
    api_key = os.environ.get("MUAPI_API_KEY", "").strip()
    if not api_key:
        raise MuAPITTSError("MUAPI_API_KEY is not set")

    api_base = _validate_api_base(
        args.api_base.rstrip("/"), allow_loopback_http=args.allow_loopback_http
    )
    if args.volume is not None and not 0.1 <= args.volume <= 10.0:
        raise MuAPITTSError("volume must be between 0.1 and 10.0")
    if args.pitch is not None and not -12 <= args.pitch <= 12:
        raise MuAPITTSError("pitch must be between -12 and 12")

    payload: dict[str, Any] = {
        "prompt": args.text,
        "voice_id": args.voice_id,
        "format": args.format,
    }
    optional = {
        "volume": args.volume,
        "pitch": args.pitch,
        "emotion": args.emotion,
        "english_normalization": args.english_normalization,
        "sample_rate": args.sample_rate,
        "bitrate": args.bitrate,
        "channel": args.channel,
        "language_boost": args.language_boost,
    }
    payload.update({key: value for key, value in optional.items() if value is not None})

    # Generation POST is intentionally issued exactly once.
    model_path = quote(args.model, safe="")
    prediction = _json_request(f"{api_base}/{model_path}", api_key, payload)
    prediction_id = _prediction_id(prediction)

    delay = args.poll_interval
    for attempt in range(args.max_polls):
        if attempt:
            time.sleep(delay)
            delay = min(delay * 1.5, args.max_poll_interval)

        current = _response_data(prediction) if attempt == 0 else _response_data(
            _json_request(
                f"{api_base}/predictions/{quote(prediction_id, safe='')}/result",
                api_key,
                attempts=3,
            )
        )
        status = str(current.get("status", "")).lower()
        if status in {"completed", "succeeded", "success"}:
            output = Path(args.output).expanduser()
            _download(
                _output_url(current), output, allow_loopback_http=args.allow_loopback_http
            )
            return output
        if status in TERMINAL_FAILURES:
            detail = current.get("error") or current.get("message") or status
            raise MuAPITTSError(f"MuAPI prediction {status}: {detail}")

    raise MuAPITTSError(f"MuAPI prediction did not finish after {args.max_polls} polls")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", help="Text to convert to speech")
    parser.add_argument("--output", required=True, help="Destination audio file")
    parser.add_argument(
        "--model", default=DEFAULT_MODEL, help="Current MuAPI text-to-audio model ID"
    )
    parser.add_argument("--voice-id", default="Friendly_Person", help="MuAPI voice ID")
    parser.add_argument(
        "--format", choices=("mp3", "wav", "pcm", "flac"), default="mp3"
    )
    parser.add_argument("--volume", type=float, default=None)
    parser.add_argument("--pitch", type=int, default=None)
    parser.add_argument("--emotion", default=None)
    parser.add_argument("--english-normalization", action="store_true")
    parser.add_argument("--sample-rate", type=int, default=None)
    parser.add_argument("--bitrate", type=int, default=None)
    parser.add_argument("--channel", type=int, choices=(1, 2), default=None)
    parser.add_argument("--language-boost", default=None)
    parser.add_argument("--max-polls", type=int, default=60, help="Maximum prediction checks")
    parser.add_argument(
        "--poll-interval", type=float, default=1.5, help="Initial delay between checks"
    )
    parser.add_argument(
        "--max-poll-interval", type=float, default=8.0, help="Maximum polling delay"
    )
    parser.add_argument(
        "--api-base",
        default=os.environ.get("MUAPI_API_BASE", DEFAULT_API_BASE),
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--allow-loopback-http", action="store_true", help=argparse.SUPPRESS)
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
    except MuAPITTSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
