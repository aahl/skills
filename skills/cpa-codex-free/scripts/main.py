# /// script
# requires-python = ">=3.11"
# dependencies = ["curl_cffi"]
# ///
import os
import re
import time
import json
import secrets
import hashlib
import base64
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass
from curl_cffi import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

MAIL_API_KEY = os.getenv("MAIL_API_KEY", "")
MAIL_API_BASE = "https://mail.chatgpt.org.uk/api"

AUTH_BASE = "https://auth.openai.com"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
REDIRECT_URI = "http://localhost:1455/auth/callback"


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str


class OpenAIService:
    def __init__(self, proxy: str = None):
        if proxy is None:
            proxy = os.getenv("HTTP_PROXY")
        self.session = requests.Session(
            proxies={"http": proxy, "https": proxy} if proxy else None,
            impersonate="chrome",
            timeout=60,
        )
        self.common_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }

    def _safe_json_decode_cookie(self, cookie_name: str):
        raw_val = self.session.cookies.get(cookie_name, "")
        if not raw_val: return {}
        try:
            payload = raw_val.split(".")[0]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
        except Exception as e:
            logger.error(f"Decode cookie {cookie_name} failed: {e}")
            return {}

    def get_email(self) -> str:
        """获取临时邮箱"""
        text = None
        for _ in range(3):
            resp = self.session.get(f"{MAIL_API_BASE}/generate-email", headers={"X-API-Key": MAIL_API_KEY})
            text = resp.text
            if resp.status_code == 200:
                return resp.json()["data"]["email"]
            time.sleep(1)
        raise RuntimeError(f"Failed to generate email: {text}")

    def get_otp_code(self, email: str) -> str:
        """轮询获取验证码"""
        regex = r"(?<!\d)(\d{6})(?!\d)"
        for _ in range(20):
            resp = self.session.get(
                f"{MAIL_API_BASE}/emails?email={email}",
                headers={"X-API-Key": MAIL_API_KEY}
            )
            if resp.status_code == 200:
                emails = resp.json().get("data", {}).get("emails", [])
                for msg in emails:
                    if "openai" in msg.get("from_address", "").lower():
                        content = msg.get("subject", "") + msg.get("html_content", "")
                        match = re.search(regex, content)
                        if match: return match.group(1)
            time.sleep(3)
        raise TimeoutError("OTP code timeout")

    def create_oauth_payload(self) -> OAuthStart:
        state = secrets.token_urlsafe(16)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

        params = {
            "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": REDIRECT_URI,
            "scope": "openid email profile offline_access", "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256",
            "prompt": "login", "id_token_add_organizations": "true", "codex_cli_simplified_flow": "true",
        }
        return OAuthStart(f"{AUTH_BASE}/oauth/authorize?{urlencode(params)}", state, verifier)

    def register(self) -> str:
        # 1. 环境准备
        email = self.get_email()
        logger.info(f"Using email: {email}")

        oauth = self.create_oauth_payload()
        self.session.get(oauth.auth_url)
        did = self.session.cookies.get("oai-did")
        logger.info("did: %s", did)

        # 2. Sentinel 校验
        sen_resp = self.session.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "origin": "https://sentinel.openai.com",
                "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "content-type": "text/plain;charset=UTF-8",
            },
            data=f'{{"p":"","id":"{did}","flow":"authorize_continue"}}',
        )
        sen_token = sen_resp.json()["token"]

        # 3. 提交邮箱
        resp = self.session.post(
            f"{AUTH_BASE}/api/accounts/authorize/continue",
            headers={
                **self.common_headers,
                "referer": f"{AUTH_BASE}/create-account",
                "openai-sentinel-token": json.dumps({"p": "", "t": "", "c": sen_token, "id": did, "flow": "authorize_continue"}),
            },
            data=json.dumps({"username": {"value": email, "kind": "email"}, "screen_hint": "signup"}, separators=(',', ':')),
        )
        logger.info("authorize/continue status: %s", resp.status_code)

        # 4. 发送并验证 OTP
        resp = self.session.post(
            f"{AUTH_BASE}/api/accounts/passwordless/send-otp",
            headers={**self.common_headers, "referer": f"{AUTH_BASE}/create-account/password"},
            data=""
        )
        logger.info("passwordless/send-otp status: %s", resp.status_code)

        code = self.get_otp_code(email)
        resp = self.session.post(
            f"{AUTH_BASE}/api/accounts/email-otp/validate",
            headers={**self.common_headers, "referer": f"{AUTH_BASE}/email-verification"},
            data=json.dumps({"code": code}, separators=(',', ':'))
        )
        logger.info("email-otp/validate status: %s", resp.status_code)

        # 5. 创建个人资料并获取 Workspace
        resp = self.session.post(
            f"{AUTH_BASE}/api/accounts/create_account",
            headers={**self.common_headers, "referer": f"{AUTH_BASE}/about-you"},
            data=json.dumps({"name": "Neo", "birthdate": "2000-02-20"}, separators=(',', ':')),
        )
        logger.info("accounts/create_account status: %s", resp.status_code)

        auth_data = self._safe_json_decode_cookie("oai-client-auth-session")
        if "workspaces" not in auth_data:
            raise RuntimeError(f"Register failed: No workspaces in session. Data: {auth_data}")

        workspace_id = auth_data["workspaces"][0]["id"]
        logger.info(f"Workspace ID: {workspace_id}")

        # 6. 选择 Workspace 并完成 OAuth 回调
        sel_resp = self.session.post(
            f"{AUTH_BASE}/api/accounts/workspace/select",
            headers={
                **self.common_headers,
                "referer": f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent",
            },
            json={"workspace_id": workspace_id}
        )

        # 7. 自动跟随重定向获取最终 Callback URL
        curr_url = sel_resp.json()["continue_url"]
        for _ in range(3):
            r = self.session.get(curr_url, allow_redirects=False)
            curr_url = r.headers.get("Location")
            if not curr_url: break
            if "code=" in curr_url: break

        # 8. 兑换最终 Token
        return self._exchange_token(curr_url, oauth)

    def _exchange_token(self, callback_url: str, oauth: OAuthStart) -> str:
        params = parse_qs(urlparse(callback_url).query)
        code = params.get("code", [""])[0]

        resp = self.session.post(
            f"{AUTH_BASE}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": oauth.code_verifier,
            }
        )
        # 格式化最终结果
        res = resp.json()
        claims = self._decode_jwt_part(res.get("id_token", ""))

        return json.dumps({
            "type": "codex",
            "email": claims.get("email"),
            "account_id": claims.get("https://api.openai.com/auth", {}).get("chatgpt_account_id"),
            "expired": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + int(res.get("expires_in", 0)))),
            "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time())),
            "refresh_token": res.get("refresh_token"),
            "id_token": res.get("id_token"),
            "access_token": res.get("access_token"),
        }, indent=2)

    def _decode_jwt_part(self, token: str):
        if token.count(".") < 2: return {}
        payload = token.split(".")[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))


def run():
    service = OpenAIService()
    try:
        return service.register()
    except Exception as e:
        return f"Error: {e}"


if __name__ == "__main__":
    print(run())
