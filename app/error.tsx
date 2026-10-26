"use client";

export default function ErrorPage({ reset }: { error: Error; reset: () => void }) {
  return <main className="page-loader"><div className="error-page"><span className="eyebrow">MIZZE / TÀI KHOẢN</span><h1>Chưa thể mở trang</h1><p>Hãy thử lại sau ít phút. Các liên kết thiết bị của bạn vẫn được lưu trong hệ thống.</p><button className="button primary" onClick={reset}>Thử lại</button></div></main>;
}
