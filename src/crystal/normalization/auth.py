from dataclasses import dataclass
from datetime import datetime
from typing import Any
from crystal.timeutil import now_vietnam, to_vietnam


@dataclass(frozen=True)
class AuthEvent:
    event_uid: str
    event_id: int
    event_time: datetime
    target_host: str
    account: str
    source_ip: str | None
    logon_type: str | None
    status: str | None
    source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_uid": self.event_uid,
            "event_type": {4624:"auth.success",4625:"auth.failure",4740:"auth.account_locked",
                           4771:"auth.kerberos_preauth_failure",4776:"auth.ntlm_validation"}.get(self.event_id,"auth.unknown"),
            "event_id": self.event_id,
            "event_time": to_vietnam(self.event_time).isoformat(),
            "target_host": self.target_host,
            "account": self.account,
            "source_ip": self.source_ip,
            "logon_type": self.logon_type,
            "status": self.status,
            "source": self.source,
        }


def normalize_auth(raw: dict[str, Any]) -> AuthEvent | None:
    event_id = int(raw.get("event_id", 0))
    if event_id not in {4624, 4625, 4740, 4771, 4776}:
        return None
    fields = raw.get("event_data", {})
    account = (fields.get("TargetUserName") or fields.get("TargetUser") or
               fields.get("AccountName") or fields.get("SubjectUserName") or "unknown")
    ip = fields.get("IpAddress") or fields.get("ClientAddress") or fields.get("Workstation")
    if ip in {"-", "::1", "127.0.0.1", "localhost"}:
        ip = None if ip == "-" else ip
    when = raw.get("time_created")
    # Nếu event thiếu thời gian hợp lệ, dùng giờ hiện tại để bản ghi vẫn xử lý được.
    stamp = to_vietnam(when) or now_vietnam()
    return AuthEvent(str(raw.get("event_uid") or raw.get("record_id") or f"{event_id}:{stamp.isoformat()}"),
                     event_id, stamp,
                     str(raw.get("computer") or raw.get("target_host") or "unknown"),
                     str(account), str(ip) if ip else None,
                     fields.get("LogonType"), fields.get("Status") or fields.get("FailureCode"),
                     str(raw.get("channel") or "Security"))
