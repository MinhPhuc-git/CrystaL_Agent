# CrystaL

CrystaL thu thập log đăng nhập Windows và phát hiện dấu hiệu brute force.

## Chạy agent

Mở PowerShell trong thư mục `CrystaL`:

```powershell
.\.venv\Scripts\Activate.ps1
python -m crystal.cli.main run
```

Dừng bằng `Ctrl+C`. Nếu agent không đọc được log, mở PowerShell bằng quyền Administrator.

## Log

- Raw: `data/raw/security-events.jsonl`
- Đã chuẩn hóa: `data/logs/`
- Thời gian log dùng giờ Việt Nam.

SQLite đang tắt. Agent không lưu kết quả phân tích vào DB. Kết quả chỉ hiện khi agent đang chạy.

Cấu hình agent nằm trong `CrystaL/.env`. Xem các giá trị mẫu trong `.env.example`.
