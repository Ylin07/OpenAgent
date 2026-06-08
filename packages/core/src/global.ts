import path from "path"
import fs from "fs/promises"
import fsSync from "fs"
import { xdgData, xdgCache, xdgConfig, xdgState } from "xdg-basedir"
import os from "os"
import { Context, Effect, Layer } from "effect"
import { Flock } from "./util/flock"
import { Flag } from "./flag/flag"

const app = "openagent"
const legacy = "opencode"

// backward compat: map all OPENCODE_* env vars to OPENAGENT_*
for (const key of Object.keys(process.env)) {
  if (key.startsWith("OPENCODE_")) {
    const target = "OPENAGENT_" + key.slice(8)
    if (!process.env[target]) process.env[target] = process.env[key]
  }
}

function resolve(dirFn: string | undefined | null, base: string) {
  if (!dirFn) return path.join(os.homedir(), ".local", "share", app, base)
  const newPath = path.join(dirFn, app)
  const oldPath = path.join(dirFn, legacy)
  return fsSync.existsSync(oldPath) ? oldPath : newPath
}

const data = resolve(xdgData, "")
const cache = resolve(xdgCache, "")
const config = resolve(xdgConfig, "")
const state = resolve(xdgState, "")
const tmp = path.join(os.tmpdir(), app)

const paths = {
  get home() {
    return process.env.OPENAGENT_TEST_HOME ?? os.homedir()
  },
  data,
  bin: path.join(cache, "bin"),
  log: path.join(data, "log"),
  repos: path.join(data, "repos"),
  cache,
  config,
  state,
  tmp,
}

export const Path = paths

Flock.setGlobal({ state })

await Promise.all([
  fs.mkdir(Path.data, { recursive: true }),
  fs.mkdir(Path.config, { recursive: true }),
  fs.mkdir(Path.state, { recursive: true }),
  fs.mkdir(Path.tmp, { recursive: true }),
  fs.mkdir(Path.log, { recursive: true }),
  fs.mkdir(Path.bin, { recursive: true }),
  fs.mkdir(Path.repos, { recursive: true }),
])

export class Service extends Context.Service<Service, Interface>()("@openagent/Global") {}

export interface Interface {
  readonly home: string
  readonly data: string
  readonly cache: string
  readonly config: string
  readonly state: string
  readonly tmp: string
  readonly bin: string
  readonly log: string
  readonly repos: string
}

export function make(input: Partial<Interface> = {}): Interface {
  return {
    home: Path.home,
    data: Path.data,
    cache: Path.cache,
    config: Flag.OPENAGENT_CONFIG_DIR ?? Path.config,
    state: Path.state,
    tmp: Path.tmp,
    bin: Path.bin,
    log: Path.log,
    repos: Path.repos,
    ...input,
  }
}

export const layer = Layer.effect(
  Service,
  Effect.sync(() => Service.of(make())),
)

export const defaultLayer = layer

export const layerWith = (input: Partial<Interface>) =>
  Layer.effect(
    Service,
    Effect.sync(() => Service.of(make(input))),
  )

export * as Global from "./global"
