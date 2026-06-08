import path from "path"
import os from "os"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const dir = path.resolve(__dirname, "..")

process.chdir(dir)

const modelsUrl = process.env.OPENAGENT_MODELS_URL || process.env.OPENCODE_MODELS_URL || "https://models.dev"
const cacheFile = process.env.MODELS_DEV_API_JSON
  || [path.join(os.homedir(), ".cache", "openagent", "models.json"), path.join(os.homedir(), ".cache", "opencode", "models.json")]
     .find((f) => { try { return require("fs").existsSync(f) } catch { return false } })
  || path.join(os.homedir(), ".cache", "openagent", "models.json")
export const modelsData = process.env.MODELS_DEV_API_JSON
  ? await Bun.file(process.env.MODELS_DEV_API_JSON).text()
  : await fetch(`${modelsUrl}/api.json`)
      .then((x) => x.text())
      .catch(async () => {
        console.log(`models.dev unreachable, using cached ${cacheFile}`)
        return await Bun.file(cacheFile).text()
      })
console.log("Loaded models.dev snapshot")
