# Legal-Tool-HSMT

Công cụ đang phát triển cho nhân sự pháp lý/đấu thầu QI, hướng tới hỗ trợ chuẩn bị và rà soát hồ sơ mời thầu (HSMT).

## Hiện có

- Lõi Python đọc văn bản PDF có giới hạn, lưu bản gốc theo gói hồ sơ và kiểm tra tính toàn vẹn.
- API lưu, mở và liệt kê bản chụp chuẩn bị rà soát; chưa phải kết luận pháp lý.
- Demo giao diện riêng: xem các tab HSMT, Chương V, Mục 3; chọn hàng hóa, xem thông số và nguồn minh họa. Toàn bộ dữ liệu là giả.

## Chạy thử demo

Cần Python và Tk. Mở terminal tại thư mục mã nguồn đã tải, chạy:

```sh
python -X utf8 -B tools/standalone_display/display.py
```

Demo chỉ đọc dữ liệu mẫu kèm theo; không đọc PDF thật, kết nối lõi hay lưu chỉnh sửa. [Hướng dẫn và phím tắt](tools/standalone_display/README.md).

## Đang phát triển

Trích yêu cầu từ HSMT/Chương V thật và đối chiếu với kho hồ sơ QI đang phát triển. Bộ trích xuất và giao diện cho hồ sơ thật còn chờ nghiệm thu. Nhân sự phụ trách vẫn cần rà soát.

## Giới hạn V1

Mỗi kho chỉ hỗ trợ một phiên Windows, với các tiến trình do ứng dụng phối hợp. Truy cập đồng thời cùng kho từ phiên/tài khoản khác không được hỗ trợ; kiểm thử liên phiên: **NOT_TESTED**. Không tự động chuyển đổi kho; không nâng cấp khi kho đang hoạt động.

## Dành cho người đóng góp

Mã nguồn/test: tối đa 100000 byte mỗi tệp. Tệp quá cỡ: chưa có. Ghi đường dẫn, số byte, lý do, trạng thái duyệt; chặn đến khi được duyệt, không tự xóa.

[Tham chiếu API và phạm vi V1 tại bản 22cb30a (cố định)](https://github.com/tanntran2000/Legal-Tool-HSMT/blob/22cb30a464bb915a78852a669faa2ca43a4173f8/README.md).
