import base64
import json
from typing import Dict, Optional
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request


class TwilioSender:
    def __init__(
        self,
        *,
        account_sid: str,
        auth_token: str,
        from_number: str = "",
        messaging_service_sid: str = "",
        timeout_seconds: float = 5.0,
    ):
        self.account_sid = str(account_sid or "").strip()
        self.auth_token = str(auth_token or "").strip()
        self.from_number = str(from_number or "").strip()
        self.messaging_service_sid = str(messaging_service_sid or "").strip()
        self.timeout_seconds = float(timeout_seconds)

    def _is_configured(self) -> bool:
        if not self.account_sid or not self.auth_token:
            return False
        return bool(self.from_number or self.messaging_service_sid)

    def send_sms(self, to_phone: str, message: str) -> Dict[str, Optional[str]]:
        phone_norm = str(to_phone or "").strip()
        if not phone_norm:
            return {"status": "failed", "error": "Missing phone", "target": phone_norm}
        if not self._is_configured():
            return {"status": "failed", "error": "Twilio credentials not configured", "target": phone_norm}

        payload = {"To": phone_norm, "Body": message}
        if self.messaging_service_sid:
            payload["MessagingServiceSid"] = self.messaging_service_sid
        else:
            payload["From"] = self.from_number

        encoded_body = urllib_parse.urlencode(payload).encode("utf-8")
        endpoint = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"
        req = urllib_request.Request(endpoint, data=encoded_body, method="POST")
        auth_raw = f"{self.account_sid}:{self.auth_token}".encode("utf-8")
        req.add_header("Authorization", f"Basic {base64.b64encode(auth_raw).decode('ascii')}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with urllib_request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8")
                code = int(resp.getcode() or 0)
                parsed = json.loads(body) if body else {}
                if 200 <= code < 300:
                    return {
                        "status": "sent",
                        "target": phone_norm,
                        "http_status": code,
                        "provider": "twilio",
                        "message_sid": str(parsed.get("sid", "")),
                        "error": "",
                    }
                return {
                    "status": "failed",
                    "target": phone_norm,
                    "http_status": code,
                    "provider": "twilio",
                    "error": str(parsed.get("message") or f"Twilio HTTP {code}"),
                }
        except urllib_error.HTTPError as exc:
            details = ""
            try:
                details = exc.read().decode("utf-8")
            except Exception:
                details = ""
            return {
                "status": "failed",
                "target": phone_norm,
                "provider": "twilio",
                "http_status": exc.code,
                "error": details[:300] or f"Twilio HTTPError {exc.code}",
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "failed",
                "target": phone_norm,
                "provider": "twilio",
                "error": str(exc),
            }
