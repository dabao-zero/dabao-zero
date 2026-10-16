import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [svelte()],
  server: { proxy: { "/v1": "http://127.0.0.1:8000" } },
  resolve: process.env.VITEST ? { conditions: ["browser"] } : undefined,
  test: { environment: "jsdom", include: ["src/**/*.test.ts"] },
});
