import { describe, expect, test } from "bun:test"
import { isImageAttachment, isMedia, isPdfAttachment, sniffAttachmentMime } from "./media"

describe("media utilities", () => {
  test("classifies supported media attachments", () => {
    expect(isPdfAttachment("application/pdf")).toBe(true)
    expect(isMedia("image/png")).toBe(true)
    expect(isMedia("application/pdf")).toBe(true)
    expect(isMedia("text/plain")).toBe(false)
  })

  test("excludes SVG and vendor spreadsheet images from image attachments", () => {
    expect(isImageAttachment("image/png")).toBe(true)
    expect(isImageAttachment("image/svg+xml")).toBe(false)
    expect(isImageAttachment("image/vnd.fastbidsheet")).toBe(false)
  })

  test("sniffs common image and PDF magic bytes", () => {
    expect(sniffAttachmentMime(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), "text/plain")).toBe(
      "image/png",
    )
    expect(sniffAttachmentMime(new Uint8Array([0xff, 0xd8, 0xff]), "text/plain")).toBe("image/jpeg")
    expect(sniffAttachmentMime(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]), "text/plain")).toBe(
      "application/pdf",
    )
    expect(sniffAttachmentMime(new Uint8Array([0x00, 0x01]), "text/plain")).toBe("text/plain")
  })
})
