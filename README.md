# Legal-Tool-HSMT
Tool Pháp lý nội bộ

## Phạm vi hỗ trợ V1

Mỗi kho dữ liệu chỉ dùng trong một phiên Windows. Hỗ trợ nhiều tiến trình do ứng dụng quản lý và phối hợp với nhau trong cùng phiên.

Truy cập đồng thời cùng kho từ phiên Windows hoặc tài khoản khác không được hỗ trợ trong V1. Kiểm thử giữa các phiên: **NOT_TESTED**.

Cơ chế phối hợp Global hiện có giữ nguyên. Đây là giới hạn hỗ trợ, không phải cơ chế mới ngăn truy cập ngoài phạm vi hoặc bằng chứng hoạt động giữa các phiên.

## Saved preparation test-store API
Creation stays at schema 1. Explicit `upgrade_preparation_store(root)` upgrades an admitted, quiescent existing store to schema 2 atomically and idempotently. Old binaries refuse schema 2. Ordinary open never migrates; no live upgrade is authorized here.

`save_preparation(root, package_id, preparation_id, payload)` appends an immutable snapshot; `open_preparation(root, package_id, preparation_id)` verifies saved checksum and managed sources without reparsing external files. Same UUID/content retries return stored time/checksum; conflicting reuse rejects.

Payload v1 has exactly `payload_version`, `checklist_row`, `doc_refs`, `source_spans`. One row has `name/status/next_action/submission_summary`; status remains a recorded decision, not legal approval. Up to 8 DocRefs bind `package_id/package_uuid/file_id/file_version/sha256/byte_count/managed_relative_path` in this store, including a separate QI package. Spans use `doc_ref/page/locator/start/end/text`: ref index, 1-based page, exact persisted text offsets. Canonical UTF-8 JSON is at most64KiB. Active imports, relevant owner HOLD, uncertain integrity and projected database/journal budget block writes. Tests use synthetic fixtures; real-source parser/UI acceptance is pending.
