import { describe, expect, test } from "bun:test"
import { getDirectory, getFileExtension, getFilename, getFilenameTruncated, truncateMiddle } from "./path"

describe("path utilities", () => {
  test("extracts filenames from POSIX and Windows-style paths", () => {
    expect(getFilename("/tmp/example.txt")).toBe("example.txt")
    expect(getFilename("C:\\tmp\\example.txt")).toBe("example.txt")
    expect(getFilename("/tmp/folder/")).toBe("folder")
  })

  test("extracts directory with normalized slash suffix", () => {
    expect(getDirectory("/tmp/example.txt")).toBe("/tmp/")
    expect(getDirectory("C:\\tmp\\example.txt")).toBe("C:/tmp/")
  })

  test("extracts the extension using current behavior", () => {
    expect(getFileExtension("archive.tar.gz")).toBe("gz")
    expect(getFileExtension("README")).toBe("README")
  })

  test("truncates filenames while preserving the extension when possible", () => {
    expect(getFilenameTruncated("/tmp/very-long-name.txt", 12)).toBe("very-lo\u2026.txt")
    expect(truncateMiddle("abcdefghijklmnopqrstuvwxyz", 9)).toBe("abcd\u2026wxyz")
  })
})
