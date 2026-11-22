import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Sans_Arabic, JetBrains_Mono, Readex_Pro } from "next/font/google";
import { AppShell } from "@/components/AppShell";
import { ToastProvider } from "@/components/ui";
import { I18nProvider, tr } from "@/lib/i18n";
import "./globals.css";

const plex = IBM_Plex_Sans({ variable: "--font-plex", subsets: ["latin"], weight: ["400", "500", "600", "700"] });
const plexAr = IBM_Plex_Sans_Arabic({ variable: "--font-plex-ar", subsets: ["arabic"], weight: ["400", "500", "600", "700"] });
const readex = Readex_Pro({ variable: "--font-readex", subsets: ["arabic", "latin"], weight: "variable", axes: ["HEXP"] });
const mono = JetBrains_Mono({ variable: "--font-mono-jb", subsets: ["latin"], weight: ["400", "600", "700"] });

export const metadata: Metadata = {
  title: "Three Bees (3B) — Security Center",
  description: "Scam detection, email security and threat correlation for the UAE",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ar" dir="rtl">
      <body className={`${plex.variable} ${plexAr.variable} ${readex.variable} ${mono.variable} font-sans antialiased`}>
        <I18nProvider>
          <ToastProvider>
            <AppShell>{children}</AppShell>
          </ToastProvider>
        </I18nProvider>
      </body>
    </html>
  );
}
