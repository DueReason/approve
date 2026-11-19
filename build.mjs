// Bundles the action and the SDK into the one file action.yml runs, so the
// runner needs nothing but its own Node.
import { build } from "esbuild";

await build({
  entryPoints: ["src/main.ts"],
  outfile: "dist/index.mjs",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  legalComments: "none",
});
