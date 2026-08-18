from __future__ import annotations

import argparse
import importlib.util
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / "skills" / "muapi-tts" / "scripts" / "muapi_tts.py"
SPEC = importlib.util.spec_from_file_location("muapi_tts", SCRIPT)
assert SPEC and SPEC.loader
muapi_tts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(muapi_tts)


class FakeMuAPIHandler(BaseHTTPRequestHandler):
    post_count = 0
    get_count = 0
    media_api_key = None
    media_authorization = None
    post_body = None

    def log_message(self, format, *args):
        pass

    def _json(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).post_count += 1
        if not self.assert_api_key() or not self.assertEqualPath(
            "/api/v1/minimax-speech-2.6-hd"
        ):
            return
        length = int(self.headers.get("Content-Length", "0"))
        type(self).post_body = json.loads(self.rfile.read(length))
        self._json({"request_id": "req-1", "status": "processing"})

    def do_GET(self):
        if self.path == "/media/output.mp3":
            type(self).media_api_key = self.headers.get("x-api-key")
            type(self).media_authorization = self.headers.get("Authorization")
            body = b"ID3\x04\x00\x00test-audio"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        type(self).get_count += 1
        if not self.assert_api_key() or not self.assertEqualPath(
            "/api/v1/predictions/req-1/result"
        ):
            return
        if type(self).get_count == 1:
            self.send_error(404)
            return
        port = self.server.server_address[1]
        self._json(
            {
                "id": "req-1",
                "status": "completed",
                "outputs": [f"http://127.0.0.1:{port}/media/output.mp3"],
            }
        )

    def assert_api_key(self):
        if self.headers.get("x-api-key") != "test-key":
            self.send_error(401)
            return False
        return True

    def assertEqualPath(self, expected):
        if self.path != expected:
            self.send_error(404)
            return False
        return True


class MuAPITTSTest(unittest.TestCase):
    def setUp(self):
        FakeMuAPIHandler.post_count = 0
        FakeMuAPIHandler.get_count = 0
        FakeMuAPIHandler.media_api_key = None
        FakeMuAPIHandler.media_authorization = None
        FakeMuAPIHandler.post_body = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeMuAPIHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_generates_polls_and_downloads_without_forwarding_credentials(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "speech.mp3"
            args = argparse.Namespace(
                api_base=f"http://127.0.0.1:{self.server.server_address[1]}/api/v1",
                allow_loopback_http=True,
                text="hello",
                output=str(output),
                model="minimax-speech-2.6-hd",
                voice_id="Friendly_Person",
                format="mp3",
                volume=None,
                pitch=None,
                emotion=None,
                english_normalization=False,
                sample_rate=None,
                bitrate=None,
                channel=None,
                language_boost=None,
                max_polls=3,
                poll_interval=0,
                max_poll_interval=0,
            )
            with (
                patch.dict(
                    os.environ,
                    {
                        "MUAPI_API_KEY": "test-key",
                        "NO_PROXY": "127.0.0.1,localhost",
                        "no_proxy": "127.0.0.1,localhost",
                    },
                ),
                patch.object(muapi_tts.time, "sleep"),
            ):
                result = muapi_tts.generate(args)

            self.assertEqual(result, output)
            self.assertTrue(output.read_bytes().startswith(b"ID3"))
            self.assertEqual(FakeMuAPIHandler.post_count, 1)
            self.assertEqual(FakeMuAPIHandler.get_count, 2)
            self.assertIsNone(FakeMuAPIHandler.media_api_key)
            self.assertIsNone(FakeMuAPIHandler.media_authorization)
            self.assertEqual(FakeMuAPIHandler.post_body["prompt"], "hello")
            self.assertEqual(FakeMuAPIHandler.post_body["voice_id"], "Friendly_Person")

    def test_rejects_non_https_remote_urls(self):
        with self.assertRaisesRegex(muapi_tts.MuAPITTSError, "non-HTTPS"):
            muapi_tts._validate_url("http://example.com/output.mp3")

    def test_rejects_credential_bearing_urls(self):
        with self.assertRaisesRegex(muapi_tts.MuAPITTSError, "credential-bearing"):
            muapi_tts._validate_url("https://user:pass@example.com/output.mp3")

    def test_rejects_untrusted_api_host(self):
        with self.assertRaisesRegex(muapi_tts.MuAPITTSError, "untrusted host"):
            muapi_tts._validate_api_base("https://example.com/api/v1")

    def test_rejects_wrong_muapi_api_path(self):
        with self.assertRaisesRegex(muapi_tts.MuAPITTSError, "must end with /api/v1"):
            muapi_tts._validate_api_base("https://api.muapi.ai/v1")

    def test_requires_api_key_before_submission(self):
        args = argparse.Namespace(api_base=muapi_tts.DEFAULT_API_BASE)
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(muapi_tts.MuAPITTSError, "MUAPI_API_KEY"),
        ):
            muapi_tts.generate(args)
        self.assertEqual(FakeMuAPIHandler.post_count, 0)

    def test_api_base_can_be_overridden_for_testing(self):
        with patch.dict(
            os.environ,
            {"MUAPI_API_BASE": "https://api.muapi.ai/v1"},
            clear=True,
        ):
            args = muapi_tts.build_parser().parse_args(["hello", "--output", "out.mp3"])
        self.assertEqual(args.api_base, "https://api.muapi.ai/v1")


if __name__ == "__main__":
    unittest.main()
