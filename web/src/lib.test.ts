import { describe, expect, it } from "vitest";
import { fileCategory, formatBytes, formatRelativeDate, initials, safeDownloadName } from "./lib";

describe("file presentation helpers", () => {
  it("formats byte values without losing unit meaning", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1024)).toBe("1 KB");
    expect(formatBytes(1.5 * 1024 ** 3)).toBe("1.5 GB");
  });

  it("classifies safe preview types and keeps SVG download-only", () => {
    expect(fileCategory("image/jpeg", "photo.jpg")).toBe("image");
    expect(fileCategory("image/svg+xml", "drawing.svg")).toBe("generic");
    expect(fileCategory("text/plain", "server.log")).toBe("text");
    expect(fileCategory(null, "main.go")).toBe("code");
  });

  it("sanitizes download names and creates initials", () => {
    expect(safeDownloadName("../../secrets.txt")).toBe(".._.._secrets.txt");
    expect(safeDownloadName("\u0000")).toBe("_");
    expect(initials("Ada Lovelace Byron")).toBe("AL");
  });

  it("renders recent timestamps relatively", () => {
    const now = Date.parse("2026-08-14T12:00:00Z");
    expect(formatRelativeDate("2026-08-14T11:58:00Z", now)).toBe("2 minutes ago");
    expect(formatRelativeDate(null, now)).toBe("Never");
  });
});
