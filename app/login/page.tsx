import type { Metadata } from "next";
import { LoginPage } from "../../components/portal";

export const metadata: Metadata = { title: "Đăng nhập" };
export default function Page() { return <LoginPage />; }
