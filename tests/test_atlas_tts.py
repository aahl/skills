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

SCRIPT = Path(__file__).parents[1] / "skills" / "atlas-tts" / "scripts" / "atlas_tts.py"
SPEC = importlib.util.spec_from_file_location("atlas_tts", SCRIPT)
assert SPEC and SPEC.loader
atlas_tts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(atlas_tts)


class FakeAtlasHandler(BaseHTTPRequestHandler):
    post_count = 0
    get_count = 0
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
        self.assert_authorized()
        length = int(self.headers.get("Content-Length", "0"))
        type(self).post_body = json.loads(self.rfile.read(length))
        self._json({"code": 200, "data": {"id": "pred-1", "status": "created"}})

    def do_GET(self):
        if self.path == "/media/output.mp3":
            type(self).media_authorization = self.headers.get("Authorization")
            body = b"ID3\x04\x00\x00test-audio"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        type(self).get_count += 1
        self.assert_authorized()
        if type(self).get_count == 1:
            self.send_error(404)
            return
        port = self.server.server_address[1]
        self._json(
            {
                "code": 200,
                "data": {
                    "id": "pred-1",
                    "status": "completed",
                    "outputs": [f"http://127.0.0.1:{port}/media/output.mp3"],
                },
            }
        )

    def assert_authorized(self):
        if self.headers.get("Authorization") != "Bearer test-key":
            self.send_error(401)


class AtlasTTSTest(unittest.TestCase):
    def setUp(self):
        FakeAtlasHandler.post_count = 0
        FakeAtlasHandler.get_count = 0
        FakeAtlasHandler.media_authorization = None
        FakeAtlasHandler.post_body = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeAtlasHandler)
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
                api_base=f"http://127.0.0.1:{self.server.server_address[1]}",
                allow_loopback_http=True,
                text="hello",
                output=str(output),
                model="xai/tts-v1",
                language="auto",
                voice="eve",
                codec="mp3",
                sample_rate=None,
                bit_rate=None,
                speed=1.0,
                max_polls=3,
                poll_interval=0,
                max_poll_interval=0,
            )
            with (
                patch.dict(
                    os.environ,
                    {
                        "ATLASCLOUD_API_KEY": "test-key",
                        "NO_PROXY": "127.0.0.1,localhost",
                        "no_proxy": "127.0.0.1,localhost",
                    },
                ),
                patch.object(atlas_tts.time, "sleep"),
            ):
                result = atlas_tts.generate(args)

            self.assertEqual(result, output)
            self.assertTrue(output.read_bytes().startswith(b"ID3"))
            self.assertEqual(FakeAtlasHandler.post_count, 1)
            self.assertEqual(FakeAtlasHandler.get_count, 2)
            self.assertIsNone(FakeAtlasHandler.media_authorization)
            self.assertNotIn("sample_rate", FakeAtlasHandler.post_body)
            self.assertNotIn("bit_rate", FakeAtlasHandler.post_body)

    def test_rejects_non_https_remote_urls(self):
        with self.assertRaisesRegex(atlas_tts.AtlasTTSError, "non-HTTPS"):
            atlas_tts._validate_url("http://example.com/output.mp3")

    def test_rejects_credential_bearing_urls(self):
        with self.assertRaisesRegex(atlas_tts.AtlasTTSError, "credential-bearing"):
            atlas_tts._validate_url("https://user:pass@example.com/output.mp3")

    def test_rejects_untrusted_api_host(self):
        with self.assertRaisesRegex(atlas_tts.AtlasTTSError, "untrusted host"):
            atlas_tts._validate_api_base("https://example.com/api/v1")

    def test_rejects_llm_api_path_for_media_generation(self):
        with self.assertRaisesRegex(atlas_tts.AtlasTTSError, "must end with /api/v1"):
            atlas_tts._validate_api_base("https://api.atlascloud.ai/v1")

    def test_requires_api_key_before_submission(self):
        args = argparse.Namespace(api_base=atlas_tts.DEFAULT_API_BASE)
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(atlas_tts.AtlasTTSError, "ATLASCLOUD_API_KEY"),
        ):
            atlas_tts.generate(args)
        self.assertEqual(FakeAtlasHandler.post_count, 0)

    def test_llm_base_does_not_override_media_base(self):
        with patch.dict(
            os.environ,
            {"ATLASCLOUD_API_BASE": "https://api.atlascloud.ai/v1"},
            clear=True,
        ):
            args = atlas_tts.build_parser().parse_args(["hello", "--output", "out.mp3"])
        self.assertEqual(args.api_base, atlas_tts.DEFAULT_API_BASE)


if __name__ == "__main__":
    unittest.main()
