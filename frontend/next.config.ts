import type { NextConfig } from "next";
import path from "path";

// Where the 3B backend runs, as seen from this Next server. When NEXT_PUBLIC_API_URL is empty the browser
// calls /api on the same origin and Next forwards it here — so one public link (e.g. a Cloudflare Tunnel)
// serves both the site and the API.
const BACKEND = process.env.THREEB_BACKEND_URL || "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  outputFileTracingRoot: path.join(__dirname),
  output: "standalone",
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${BACKEND}/api/:path*` }];
  },
};

export default nextConfig;
