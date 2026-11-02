import json
import subprocess
from collections.abc import Iterator
from typing import Any
from crystal.timeutil import iso_vietnam

AUTH_EVENT_IDS = (4624, 4625, 4740, 4771, 4776)
EVENT_NAMES = {4624: "Đăng nhập thành công", 4625: "Đăng nhập thất bại",
               4740: "Tài khoản bị khóa", 4771: "Kerberos xác thực thất bại",
               4776: "NTLM kiểm tra thông tin đăng nhập"}

# Windows trả về Properties theo thứ tự mẫu của từng Event ID.
# Bản đồ này gắn tên trường mà không cần đọc XML của event.
EVENT_PROPERTY_NAMES = {
    4624: ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
           "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId",
           "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName",
           "LogonGuid", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId",
           "ProcessName", "IpAddress", "IpPort", "ImpersonationLevel", "RestrictedAdminMode",
           "TargetOutboundUserName", "TargetOutboundDomainName", "VirtualAccount",
           "TargetLinkedLogonId", "ElevatedToken"),
    4625: ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
           "TargetUserSid", "TargetUserName", "TargetDomainName", "Status", "FailureReason",
           "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName",
           "WorkstationName", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId",
           "ProcessName", "IpAddress", "IpPort"),
    4740: ("TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid",
           "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "CallerComputerName"),
    4771: ("TargetUserName", "TargetDomainName", "ServiceName", "TicketOptions", "Status",
           "PreAuthType", "IpAddress", "IpPort"),
    4776: ("TargetUserName", "Workstation", "Status"),
}


def _to_record(obj: dict[str, Any]) -> dict[str, Any]:
    eid = int(obj["event_id"])
    data = dict(obj.get("event_data") or {})
    if not data:
        names = EVENT_PROPERTY_NAMES.get(eid, ())
        values = obj.get("properties") or []
        if eid == 4624 and len(values) > len(names):
            # Một số phiên bản Windows thêm RemoteCredentialGuard ở vị trí này.
            names = (*names[:22], "RemoteCredentialGuard", *names[22:])
        for index, value in enumerate(values):
            key = names[index] if index < len(names) else f"Property{index}"
            if value is not None:
                data[key] = str(value)
    name = EVENT_NAMES.get(eid, "Windows authentication event")
    account = data.get("TargetUserName") or data.get("TargetUser") or data.get("AccountName") or ""
    ip = data.get("IpAddress") or data.get("ClientAddress") or ""
    status = data.get("Status") or data.get("FailureCode") or ""
    return {
        "event_uid": f"Security:{obj.get('record_id')}:{eid}",
        "agent": "CrystaL",
        "platform": "Windows",
        "category": "Authentication",
        "source": "Windows-Security",
        "channel": "Security",
        "record_id": str(obj.get("record_id", "")),
        "event_id": eid,
        "event_name": name,
        "friendly_view": " | ".join(x for x in ["CrystaL / Windows", f"{eid} {name}",
                                                  f"Account: {account}" if account else "",
                                                  f"Source IP: {ip}" if ip and ip != "-" else "",
                                                  f"Status: {status}" if status else ""] if x),
        "time_created": iso_vietnam(obj.get("time_created")) or obj.get("time_created"),
        "computer": obj.get("computer"),
        "provider": obj.get("provider"),
        "version": obj.get("version"),
        "message": obj.get("message"),
        "event_data": data,
    }


class SecurityEventCollector:
    """Đọc event xác thực trong ngày gần nhất rồi tiếp tục nhận event mới."""

    def __init__(self, poll_seconds: float = 1.0, batch_size: int = 500) -> None:
        self.poll_seconds = poll_seconds
        self.batch_size = batch_size

    def stream(self, after_record_id: int = 0, checkpoint_time: str | None = None) -> Iterator[dict[str, Any]]:
        if __import__("os").name != "nt":
            raise OSError("Windows Security Event Log collector requires Windows")
        ids = ",".join(map(str, AUTH_EVENT_IDS))
        checkpoint_time = iso_vietnam(checkpoint_time) if checkpoint_time else ""
        checkpoint_time = (checkpoint_time or "").replace("'", "")
        ps = f"""
$ErrorActionPreference='Stop'
$ids=@({ids})
$cursor=[long]{max(0, int(after_record_id))}
$checkpointTime='{checkpoint_time}'
$startUtc=[DateTime]::UtcNow.AddDays(-1)
if ($checkpointTime) {{
  # Đọc chồng hai giây quanh checkpoint để tránh bỏ sót event sát ranh giới.
  try {{ $startUtc=[DateTimeOffset]::Parse($checkpointTime).UtcDateTime.AddSeconds(-2) }} catch {{}}
}}
$startUtcText=$startUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$latest=@()
try {{ $latest=@(Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop) }} catch {{ $latest=@() }}
# Nếu Security log bị xóa hoặc tạo lại, Record ID có thể nhỏ hơn checkpoint cũ.
if ($cursor -gt 0 -and ($latest.Count -eq 0 -or [long]$latest[0].RecordId -lt $cursor)) {{ $cursor=[long]0 }}
$names=@{{4624='Logon succeeded';4625='Logon failed';4740='Account locked out';4771='Kerberos pre-authentication failed';4776='NTLM credential validation'}}
while ($true) {{
  try {{
    $idExpr=($ids -join ' or EventID=')
    if ($cursor -gt 0) {{
      $xpath="*[System[(EventRecordID > $cursor) and (EventID=$idExpr)]]"
    }} else {{
      $xpath="*[System[(EventID=$idExpr) and TimeCreated[@SystemTime >= '$startUtcText']]]"
    }}
    $items=@(Get-WinEvent -LogName 'Security' -FilterXPath $xpath -Oldest -MaxEvents {self.batch_size} -ErrorAction Stop)
    foreach($e in $items) {{
      # Lấy trường có tên và phần mô tả thân thiện; không xuất XML.
      $properties=@($e.Properties | ForEach-Object {{ if ($null -eq $_.Value) {{ $null }} else {{ [string]$_.Value }} }})
      $message=''; try {{ $message=$e.FormatDescription() }} catch {{}}
      $o=@{{record_id=[string]$e.RecordId;event_id=$e.Id;event_name=$names[[int]$e.Id];time_created=$e.TimeCreated.ToUniversalTime().ToString('o');computer=$e.MachineName;provider=$e.ProviderName;version=$e.Version;message=$message;properties=$properties}}
      $o | ConvertTo-Json -Compress -Depth 4
      if ([long]$e.RecordId -gt $cursor) {{ $cursor=[long]$e.RecordId }}
    }}
    if ($items.Count -eq {self.batch_size}) {{ continue }}
  }} catch {{
    # Không có event mới là bình thường; các lỗi đọc khác cần báo ra ngoài.
    if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {{
      [Console]::Error.WriteLine($_.Exception.Message)
      exit 3
    }}
  }}
  Start-Sleep -Milliseconds {max(250, int(self.poll_seconds * 1000))}
}}
"""
        proc = subprocess.Popen(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", bufsize=1,
        )
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                line = line.strip()
                if line:
                    yield _to_record(json.loads(line))
            code = proc.wait()
            if code:
                detail = proc.stderr.read().strip() if proc.stderr else ""
                raise RuntimeError(f"PowerShell Security collector exited with {code}: {detail or 'no diagnostic output'}")
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
