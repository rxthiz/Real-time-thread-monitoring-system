import json
import logging
import time
from typing import Dict, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

from src.sos.twilio_sender import TwilioSender

logger = logging.getLogger(__name__)


class SmsSender:
    def __init__(
        self,
        *,
        simulation_mode: bool = True,
        webhook_url: str = "",
        provider: str = "webhook",
        timeout_seconds: float = 4.0,
        max_retries: int = 3,
        retry_delay_seconds: float = 1.0,
        twilio_account_sid: str = "",
        twilio_auth_token: str = "",
        twilio_from_number: str = "",
        twilio_messaging_service_sid: str = "",
    ):
        self.simulation = bool(simulation_mode)
        self.webhook_url = str(webhook_url or "").strip()
        self.provider = str(provider or "webhook").strip().lower()
        self.timeout_seconds = float(timeout_seconds)
        self.max_retries = max(1, int(max_retries))
        self.retry_delay_seconds = float(retry_delay_seconds)
        self.twilio_sender = TwilioSender(
            account_sid=twilio_account_sid,
            auth_token=twilio_auth_token,
            from_number=twilio_from_number,
            messaging_service_sid=twilio_messaging_service_sid,
            timeout_seconds=self.timeout_seconds,
        )

    def send_sms(self, phone: str, message: str) -> Dict[str, Optional[str]]:
        phone_norm = str(phone or "").strip()
        if not phone_norm:
            return {"status": "failed", "error": "Missing phone", "target": phone_norm}

        if self.simulation:
            logger.info("[SIMULATION] SMS to %s: %s", phone_norm, message[:180])
            return {"status": "simulated", "target": phone_norm, "error": ""}

        if self.provider == "twilio":
            return self.twilio_sender.send_sms(phone_norm, message)

        if not self.webhook_url:
            return {"status": "failed", "target": phone_norm, "error": "Webhook URL missing"}

        payload = {"to": phone_norm, "message": message}
        body = json.dumps(payload).encode("utf-8")

        last_error: Optional[str] = None
        for attempt in range(1, self.max_retries + 1):
            req = urllib_request.Request(
                self.webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib_request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    code = int(resp.getcode() or 0)
                    ok = 200 <= code < 300
                    return {
                        "status": "sent" if ok else "failed",
                        "target": phone_norm,
                        "http_status": code,
                        "error": "" if ok else f"Non-2xx status {code}",
                    }
            except urllib_error.HTTPError as exc:
                last_error = f"HTTPError {exc.code}"
            except Exception as exc:
                last_error = str(exc)
            time.sleep(self.retry_delay_seconds)
        return {"status": "failed", "target": phone_norm, "error": last_error}
