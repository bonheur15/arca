import { defineConfig } from "vitest/config";
import { loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  const apiTarget = env.ARCA_API_TARGET || "http://127.0.0.1:8080";
  return {
    plugins: [react()],
    build: {
      outDir: "dist",
      emptyOutDir: true,
      sourcemap: false,
      rolldownOptions: {
        output: {
          codeSplitting: {
            minSize: 20_000,
            groups: [
              { name: "react", test: /node_modules\/(react|react-dom)\// },
              { name: "tanstack", test: /node_modules\/@tanstack\// },
              { name: "motion", test: /node_modules\/motion\// },
              { name: "radix", test: /node_modules\/@radix-ui\// },
            ],
          },
        },
      },
    },
    server: {
      proxy: {
        "/api": apiTarget,
        "/health": apiTarget,
      },
    },
    test: {
      environment: "jsdom",
      setupFiles: "./src/test/setup.ts",
      css: true,
    },
  };
});
