# CrystaL

CrystaL thu thập log đăng nhập Windows và phát hiện dấu hiệu brute force.

## Chạy agent

Mở PowerShell bằng quyền Administrator. trong thư mục `CrystaL`:

```powershell
.\.venv\Scripts\Activate.ps1
python -m crystal.cli.main run
```

`Ctrl+C` để dừng. Nếu agent không đọc được log, 

## Log

- Raw: `data/raw/security-events.jsonl`
- Đã chuẩn hóa: `data/logs/`

Cấu hình agent nằm trong `CrystaL/.env`. Xem các giá trị mẫu trong `.env.example`.
