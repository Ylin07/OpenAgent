#!/usr/bin/env bun

import { $ } from "bun"
import fs from "fs"
import path from "path"
import { fileURLToPath } from "url"
import { createSolidTransformPlugin } from "@opentui/solid/bun-plugin"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const dir = path.resolve(__dirname, "..")

process.chdir(dir)

const generated = await import("./generate.ts")

import pkg from "../package.json"

const env = {
  OPENAGENT_CHANNEL: process.env["OPENAGENT_CHANNEL"],
  OPENAGENT_VERSION: process.env["OPENAGENT_VERSION"],
}
const scriptChannel = env.OPENAGENT_CHANNEL || (await $`git branch --show-current`.text().then((x) => x.trim())) || "dev"
const scriptVersion = env.OPENAGENT_VERSION || pkg.version

const skipInstall = process.argv.includes("--skip-install")
const sourcemapsFlag = process.argv.includes("--sourcemaps")
const plugin = createSolidTransformPlugin()

await $`rm -rf dist`

if (!skipInstall) {
  await $`bun install @opentui/core@${pkg.dependencies["@opentui/core"]}`
}

const name = `openagent-linux-x64`
const compileTarget = `bun-linux-x64`
console.log(`building ${name}`)
await $`mkdir -p dist/${name}/bin`

const localPath = path.resolve(dir, "node_modules/@opentui/core/parser.worker.js")
const rootPath = path.resolve(dir, "../../node_modules/@opentui/core/parser.worker.js")
const parserWorker = fs.realpathSync(fs.existsSync(localPath) ? localPath : rootPath)
const workerPath = "./src/cli/cmd/tui/worker.ts"

const bunfsRoot = "/$bunfs/root/"
const workerRelativePath = path.relative(dir, parserWorker).replaceAll("\\", "/")

await Bun.build({
  conditions: ["node"],
  tsconfig: "./tsconfig.json",
  plugins: [plugin],
  external: ["node-gyp"],
  format: "esm",
  minify: true,
  sourcemap: sourcemapsFlag ? "linked" : "none",
  splitting: true,
  compile: {
    autoloadBunfig: false,
    autoloadDotenv: false,
    autoloadTsconfig: true,
    autoloadPackageJson: true,
    target: compileTarget as any,
    outfile: `dist/${name}/bin/openagent`,
    execArgv: [`--user-agent=openagent/${scriptVersion}`, "--use-system-ca", "--"],
  },
  entrypoints: ["./src/index.ts", parserWorker, workerPath],
  define: {
    OPENAGENT_VERSION: `'${scriptVersion}'`,
    OPENAGENT_MODELS_DEV: generated.modelsData,
    OTUI_TREE_SITTER_WORKER_PATH: bunfsRoot + workerRelativePath,
    OPENAGENT_WORKER_PATH: workerPath,
    OPENAGENT_CHANNEL: `'${scriptChannel}'`,
    OPENAGENT_LIBC: "'glibc'",
    "process.env.OPENTUI_LIBC": JSON.stringify("glibc"),
  },
})

console.log(`Running smoke test: dist/${name}/bin/openagent --version`)
try {
  const versionOutput = await $`dist/${name}/bin/openagent --version`.text()
  console.log(`Smoke test passed: ${versionOutput.trim()}`)
} catch (e) {
  console.error(`Smoke test failed for ${name}:`, e)
  process.exit(1)
}

await $`rm -rf ./dist/${name}/bin/tui`
await Bun.file(`dist/${name}/package.json`).write(
  JSON.stringify(
    {
      name,
      version: scriptVersion,
      preferUnplugged: true,
      os: ["linux"],
      cpu: ["x64"],
    },
    null,
    2,
  ),
)
