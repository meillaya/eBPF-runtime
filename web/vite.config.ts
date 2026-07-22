// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Vite config for the kernel-v1 Sentinel Console.
//
// Dev server runs on :8080 — the only redirect URI registered with the
// dev Dex (deploy/compose/config/dex-config.yaml: http://localhost:8080/callback).
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 8080,
    strictPort: false,
    host: "127.0.0.1",
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    target: "es2022",
  },
});
