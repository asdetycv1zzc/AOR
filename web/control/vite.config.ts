import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/v1": "http://127.0.0.1:8090",
      "/ui/config": "http://127.0.0.1:8090",
      "/ui/oauth/token": "http://127.0.0.1:8090",
      "/health": "http://127.0.0.1:8090"
    }
  }
});
