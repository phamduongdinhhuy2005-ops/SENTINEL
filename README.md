# SENTINEL v2 - OWASP Security Workbench

SENTINEL v2 là ứng dụng desktop dùng Electron + React, hỗ trợ rà soát bảo mật website và mã nguồn theo định hướng OWASP. Dự án tập trung vào việc giúp người dùng phát hiện rủi ro phổ biến, quản lý findings, xuất báo cáo và dùng trợ lý AI bảo mật khi cần phân tích thêm.

Ứng dụng phù hợp cho học tập, kiểm tra nội bộ, rà soát dự án trước khi bàn giao hoặc tạo checklist bảo mật nhanh cho đội phát triển.

## Tính năng chính

- **URL Scan**: quét website/endpoint để kiểm tra header bảo mật, cookie, CORS, TLS, endpoint nhạy cảm và một số dấu hiệu rủi ro thường gặp.
- **Project Scan**: đọc source/config/dependency/CI để phát hiện pattern rủi ro như secret bị commit, dependency cũ, thiếu SRI, cấu hình bảo mật yếu.
- **Bảng findings**: gom nhóm theo OWASP, hiển thị mức độ, độ tin cậy, vị trí, trạng thái xử lý và chi tiết khuyến nghị.
- **Checklist**: tạo danh sách việc cần làm từ findings để theo dõi quá trình xử lý.
- **Lịch sử quét**: lưu lại kết quả scan, xem lại hoặc xóa từng mục lịch sử khi không cần nữa.
- **Xuất báo cáo**: xuất kết quả ra HTML hoặc JSON để chia sẻ/nộp kèm tài liệu.
- **Trợ lý AI bảo mật**: có knowledge base nội bộ; nếu cấu hình API key thì có thể gọi thêm LLM để trả lời sâu hơn.

## Yêu cầu môi trường

- Node.js `22.19.0` hoặc mới hơn
- npm `10` hoặc mới hơn
- Windows là môi trường đóng gói chính hiện tại

Kiểm tra phiên bản:

```bash
node -v
npm -v
```

## Cài đặt dự án

Clone repo và cài dependency:

```bash
git clone <repo-url>
cd sentinel-v2
npm install
```

Chạy ở chế độ phát triển:

```bash
npm run dev
```

Lệnh này khởi động Vite cho giao diện React và Electron cho ứng dụng desktop.

## Cách sử dụng nhanh

1. Mở app bằng `npm run dev`.
2. Vào tab **Quét Website** nếu muốn kiểm tra một URL public.
3. Vào tab **Quét Mã Nguồn** nếu muốn chọn thư mục dự án local để phân tích source/config/dependency.
4. Xem findings trong bảng kết quả, bấm **Chi tiết** để đọc mô tả và hướng xử lý.
5. Cập nhật trạng thái xử lý để theo dõi tiến độ.
6. Vào **Checklist** để xem danh sách việc cần làm được tạo từ kết quả quét.
7. Dùng **Xuất HTML** hoặc **Xuất JSON** nếu cần lưu/chia sẻ báo cáo.
8. Mở **Trợ lý bảo mật** nếu muốn hỏi thêm về OWASP, findings hoặc cách khắc phục.

## Cấu hình AI/API key

AI là tính năng tùy chọn. Nếu không có API key, trợ lý vẫn dùng knowledge base nội bộ để trả lời các câu hỏi cơ bản. Nếu muốn dùng LLM online, có hai cách cấu hình:

### Cách khuyến nghị: cấu hình trong app

1. Mở nút **Trợ lý bảo mật**.
2. Vào phần cấu hình API key.
3. Nhập key cho provider bạn muốn dùng, ví dụ Groq, Gemini, OpenRouter, Together hoặc HuggingFace.
4. Bấm lưu để app áp dụng ngay.

Key được lưu trong thư mục `userData` của Electron trên máy người dùng, không cần đặt chung thư mục với file `.exe`.

### Cách phụ: dùng file `.env`

Copy `.env.example` thành `.env` rồi điền key:

```bash
cp .env.example .env
```

Các biến thường dùng:

```env
GROQ_API_KEY=
GEMINI_API_KEY=
OPENROUTER_API_KEY=
TOGETHER_API_KEY=
HF_API_KEY=
```

Lưu ý: không commit file `.env` thật lên Git. Repo đã cấu hình `.gitignore` để bỏ qua `.env`.

## Các lệnh thường dùng

| Lệnh | Mục đích |
| --- | --- |
| `npm run dev` | Chạy app ở chế độ phát triển |
| `npm run lint` | Kiểm tra quy tắc code cho renderer, Electron và engine |
| `npm run typecheck` | Kiểm tra TypeScript |
| `npm test` | Chạy test bằng Vitest |
| `npm run build` | Build production vào `dist-electron/` |
| `npm run clean` | Xóa output build cũ trong `dist/` và `dist-electron/` |
| `npm run dist` | Build và đóng gói bản Windows portable |

## Đóng gói thành file EXE

Khi cần tạo bản portable cho Windows:

```bash
npm run clean
npm run dist
```

File xuất ra nằm trong thư mục `dist/`, theo mẫu:

```text
SENTINEL-v2-2.0.0-x64-portable.exe
```

Bản portable có thể gửi cho người khác chạy trực tiếp. Tuy nhiên có vài điểm cần biết:

- Nếu app chưa ký số bằng certificate, Windows SmartScreen có thể hiện cảnh báo khi mở lần đầu.
- API key AI không được đóng gói sẵn trong file `.exe`. Người nhận cần tự cấu hình trong app hoặc dùng file `.env`.
- Chỉ nên quét hệ thống/dự án mà bạn sở hữu hoặc được phép kiểm tra.

## Cấu trúc thư mục

```text
src/        Giao diện React, store, AI assistant, component UI
electron/   Electron main process và preload bridge
engine/     Scanner, rule engine, collector, report logic
public/     Asset tĩnh cho renderer
build/      Asset phục vụ đóng gói, ví dụ icon ứng dụng
scripts/    Script hỗ trợ kiểm tra môi trường
```

## Luồng build

- `npm run dev` chạy Vite và Electron ở chế độ development.
- `npm run build` chạy kiểm tra engine, typecheck rồi build production.
- Renderer được build vào `dist-electron/renderer/`.
- Electron main/preload được build vào `dist-electron/`.
- `npm run dist` dùng `electron-builder` để tạo bản Windows portable.

## Giới hạn và lưu ý an toàn

SENTINEL v2 hỗ trợ rà soát và gợi ý khắc phục, nhưng không thay thế hoàn toàn pentest thủ công. Kết quả scan nên được xem như tín hiệu ban đầu để ưu tiên kiểm tra, xác minh và xử lý.

Một số giới hạn cần biết:

- URL Scan không thể hiểu hết logic nghiệp vụ hoặc luồng đăng nhập phức tạp nếu không có cấu hình phù hợp.
- Project Scan phát hiện pattern rủi ro trong source/config/dependency, nhưng không luôn chứng minh được exploit thực tế.
- Findings có độ tin cậy khác nhau, nên cần đọc phần chi tiết trước khi kết luận.
- Không dùng công cụ để quét hệ thống bạn không có quyền kiểm tra.

## Đóng góp

Trước khi push code hoặc mở pull request, nên chạy:

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

Quy ước chi tiết nằm trong `CONTRIBUTING.md`.
