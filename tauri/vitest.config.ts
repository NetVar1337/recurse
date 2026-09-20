import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
	test: {
		include: ["src/**/*.test.ts"],
		environment: "node",
		setupFiles: ["./vitest.setup.ts"],
	},
	resolve: {
		alias: {
			"@": path.resolve(__dirname, "./src"),
		},
	},
});
