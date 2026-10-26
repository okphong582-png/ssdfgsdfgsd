# MIZZE — Key & thiết bị

Web nền đen, chỉ nhập **key, mật khẩu key, ID máy** rồi Enter. Không dùng tài khoản email.

## Chạy trên Vercel

1. Import repository này vào Vercel, chọn framework **Next.js**, Root Directory giữ `./`.
2. Thêm 4 biến môi trường ở dưới cho Production, rồi Deploy. Build command mặc định `npm run build`.
3. Khi đổi biến môi trường, Redeploy để bản đang chạy nhận cấu hình mới.

| Biến | Giá trị |
| --- | --- |
| `FIREBASE_PROJECT_ID` | Project của server key hiện tại |
| `FIREBASE_DATABASE_URL` | URL Realtime Database của cùng project |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Toàn bộ JSON tài khoản dịch vụ của project, trên một dòng |
| `MIZZE_SESSION_SECRET` | Chuỗi base64 của ít nhất 32 byte ngẫu nhiên, giữ nguyên giữa các lần deploy |

File `.env.example` chỉ liệt kê tên biến. File cấu hình thật được bàn giao riêng ở máy chủ dự án; không commit `.env.local`, thông tin key khách hàng hay JSON service account. Không đặt tiền tố `NEXT_PUBLIC_` cho các biến này.

## Luồng sử dụng

- Key + mật khẩu được kiểm tra bằng đúng SHA-256 framing `mizze-pair-v1` mà menu sử dụng. Mật khẩu phân biệt hoa/thường.
- ID máy là 64 ký tự hex được sao chép từ menu, không phải ID do trình duyệt tự tạo.
- Enter kích hoạt ID khi còn chỗ; lần đầu mới bắt đầu thời hạn. Key đã đủ thiết bị vẫn vào được trang quản lý để reset.
- Reset xóa các liên kết cũ và gắn ID mới trong **một giao dịch Firebase**. Tối đa **2 lần cho từng key trong mỗi ngày Việt Nam (UTC+7)**; làm mới lượt lúc 00:00. Reset không gia hạn key.
- Key cũ chưa có metadata quản lý được chuyển sang chế độ cần duyệt ID khi kích hoạt trên web. Key đã quản lý giữ nguyên chủ sở hữu và thời hạn. API cấp phép hiện có đọc cùng bản ghi nên từ chối ID bị gỡ sau khi phiên đã ký hiện tại hết hạn (tối đa 30 giây với key quản lý).
- Server chỉ lấy key từ phiên mã hóa để đọc hoặc reset; client không thể truyền ID của key khác. Phiên đăng xuất bị thu hồi trên Firebase.

Website và API menu dùng chung `licensesV9`. API cấp phép ở `https://www.mizzeproxy.store/v9/lease`; dùng bytes R14.33-KEYCONNECT đi kèm. Khóa RSA hiện có được giữ nguyên, không tạo identity mới.

## Kết nối key cũ và key vừa tạo

Đặt `LEGACY_FIREBASE_PROJECT_ID`, `LEGACY_FIREBASE_DATABASE_URL` và `LEGACY_FIREBASE_SERVICE_ACCOUNT_JSON` cho Firebase gốc. Khi đăng nhập một key chưa có ở kho hiện tại, server tra đúng hash Key/mật khẩu trong kho gốc và chuyển bản ghi hợp lệ sang kho mà menu dùng. Việc này diễn ra trực tiếp mỗi lần cần tra key, nên key vừa tạo ở bot/admin cũ cũng dùng được; không phụ thuộc snapshot lúc xuất source. Key đang có ở kho chính không bị bản cũ ghi đè. Key sai mật khẩu, hết hạn hoặc bị khóa không được mở lại.

Đặt `MIZZE_LICENSE_PRIVATE_KEY_BASE64` là base64 PEM RSA3072 của bộ game được bàn giao. Đây là Secret chỉ ở Production, tuyệt đối không commit vào GitHub. Server xác minh fingerprint khóa khớp `backend/game-license-public.json` trước khi ký. `/healthz` công khai fingerprint để đối chiếu với bytes; không trả khóa riêng.

## Phát triển

```sh
npm ci
# Tạo .env.local từ .env.example và điền cấu hình thật.
npm run dev
```

```sh
npm test
npm run build
npm run check
```

Để thử giao diện bằng dữ liệu giả tại localhost, đặt `MIZZE_DEMO_MODE=1`. Key thử là `MZ-DEMO-2026`, mật khẩu `Mizze-Demo-2026!`, ID thử là 64 ký tự hex. Chế độ này bị từ chối trên Vercel và production; không bật khi triển khai thật.

Các kiểm tra gồm hash đúng với menu, hạn key, duyệt ID, reset đồng thời, ranh giới 00:00, hai lượt mỗi ngày, CSRF, phiên mã hóa, chống thao tác sang key khác và thu hồi phiên đăng xuất. Dữ liệu kiểm thử là dữ liệu giả.

Hướng dẫn cấu hình môi trường: [Vercel](https://vercel.com/docs/environment-variables), [Next.js](https://nextjs.org/docs/app/guides/environment-variables).
