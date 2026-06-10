import { basename, dirname, join, relative } from "node:path"
import { stat } from "node:fs/promises"
import { tool } from "@openagent-ai/plugin"
import {
  MAX_TIMEOUT_MS,
  code,
  formatCommands,
  listFiles,
  normalizePath,
  pickLikelyBinaries,
  readSample,
  requestPermission,
  runBatch,
  section,
} from "./core.ts"
import { appendRun, writeNote } from "./workspace.ts"

const z = tool.schema

export const reverse = tool({
  description:
    "CTF Reverse 工具：对本地 challenge 文件做清单、格式、strings、readelf、objdump 等静态 triage，并记录到 .ctf。",
  args: {
    path: z.string().optional().describe("题目文件或目录，相对 session directory"),
    deep: z.boolean().optional().describe("是否运行额外静态命令，默认 false"),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
  },
  async execute(args, ctx) {
    const target = normalizePath(args.path, ctx)
    await requestPermission(ctx, "ctf_reverse", target, { path: target, deep: args.deep ?? false })
    ctx.metadata({ title: `CTF reverse: ${basename(target)}`, metadata: { path: target } })

    const targetStat = await stat(target)
    const cwd = targetStat.isDirectory() ? target : dirname(target)
    const files = targetStat.isDirectory() ? await listFiles(target, 160) : [basename(target)]
    const candidates = targetStat.isDirectory() ? pickLikelyBinaries(files).map((item) => join(target, item)) : [target]
    const primary = candidates[0] ?? target
    const commands = [
      { label: "file", command: ["file", "-b", primary], timeoutMs: args.timeoutMs },
      { label: "strings interesting", command: ["strings", "-a", "-n", "5", primary], timeoutMs: args.timeoutMs },
      { label: "readelf header", command: ["readelf", "-h", primary], timeoutMs: args.timeoutMs },
      { label: "readelf symbols", command: ["readelf", "-Ws", primary], timeoutMs: args.timeoutMs },
    ]
    if (args.deep) {
      commands.push(
        { label: "readelf sections", command: ["readelf", "-S", primary], timeoutMs: args.timeoutMs },
        { label: "objdump disasm head", command: ["objdump", "-d", primary], timeoutMs: args.timeoutMs },
      )
    }

    const sample = targetStat.isFile() ? await readSample(target).catch(() => undefined) : undefined
    const results = await runBatch(cwd, commands)
    const stringHints = results
      .find((item) => item.label === "strings interesting")
      ?.stdout.split("\n")
      .filter((line) => /flag|ctf|key|pass|secret|token|admin|xor|base64|rot|debug|license/i.test(line))
      .slice(0, 80)
      .join("\n")
    const commandText = formatCommands(results)

    await appendRun(ctx, { type: "reverse", target: primary, files: files.length })
    await writeNote(ctx, {
      category: "reverse",
      title: `Reverse triage ${basename(primary)}`,
      content: `目标: ${primary}\n文件数: ${files.length}`,
      evidence: stringHints || commandText.slice(0, 4_000),
      next: "定位输入校验路径、关键字符串引用、编码/混淆循环或解包入口。",
      tags: ["reverse", basename(primary)],
    })

    return {
      title: `CTF reverse: ${relative(ctx.worktree, primary) || primary}`,
      output: [
        section("目标", `${primary}\nworking-directory: ${cwd}`),
        section("清单", files.map((item) => `- ${item}`).join("\n")),
        sample ? section("字节样本", code(sample.subarray(0, 256).toString("hex").replace(/(.{32})/g, "$1\n"))) : "",
        section("静态命令", commandText),
        section("可疑字符串", stringHints || "默认 hint 列表未命中明显 CTF 字符串。"),
        section("下一步", [
          "- 找输入校验路径和比较逻辑。",
          "- stripped ELF 先从 entry、PLT 调用和字符串 xref 定位 main 附近逻辑。",
          "- 检查 XOR、查表、base64/hex/rot、反调试和嵌入文件。",
        ]),
      ].join("\n"),
      metadata: { path: primary, files: files.length },
    }
  },
})
