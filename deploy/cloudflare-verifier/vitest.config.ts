import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
export default defineConfig({
  plugins: [cloudflareTest({
    remoteBindings: false,
    main: "./harness.test.ts",
    miniflare: {
      compatibilityDate: "2026-08-22",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: {STORAGE: {className: "Harness", useSQLite: true}},
      r2Buckets: ["SOURCE"],
    },
  })],
  test: {include: ["worker.test.ts"]},
});
