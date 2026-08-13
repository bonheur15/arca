export function formatBytes(bytes: number, precision = 1): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(exponent === 0 ? 0 : precision).replace(/\.0$/, "")} ${units[exponent]}`;
}

export function formatRelativeDate(value: string | null | undefined, now = Date.now()): string {
  if (!value) return "Never";
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return "Unknown";
  const delta = timestamp - now;
  const absolute = Math.abs(delta);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (absolute < 60_000) return formatter.format(Math.round(delta / 1000), "second");
  if (absolute < 3_600_000) return formatter.format(Math.round(delta / 60_000), "minute");
  if (absolute < 86_400_000) return formatter.format(Math.round(delta / 3_600_000), "hour");
  if (absolute < 604_800_000) return formatter.format(Math.round(delta / 86_400_000), "day");
  return new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short", year: timestamp < new Date(now).setFullYear(new Date(now).getFullYear() - 1) ? "numeric" : undefined }).format(timestamp);
}

export function initials(name: string): string {
  return name.trim().split(/\s+/).slice(0, 2).map((part) => part[0]?.toUpperCase() ?? "").join("") || "A";
}

export function fileCategory(mimeType: string | null, name: string): "image" | "video" | "audio" | "pdf" | "text" | "archive" | "code" | "generic" {
  const mime = mimeType?.toLowerCase() ?? "";
  const extension = name.split(".").pop()?.toLowerCase() ?? "";
  if (mime.startsWith("image/") && mime !== "image/svg+xml") return "image";
  if (mime.startsWith("video/")) return "video";
  if (mime.startsWith("audio/")) return "audio";
  if (mime === "application/pdf" || extension === "pdf") return "pdf";
  if (["zip", "rar", "7z", "tar", "gz"].includes(extension)) return "archive";
  if (["js", "ts", "tsx", "jsx", "go", "rs", "py", "css", "html", "json", "yaml", "yml", "toml", "sh"].includes(extension)) return "code";
  if (mime.startsWith("text/") || ["md", "txt", "csv", "log"].includes(extension)) return "text";
  return "generic";
}

export function safeDownloadName(name: string): string {
  return name.replace(/[\u0000-\u001f\u007f/\\]/g, "_").replace(/^\.+$/, "download").slice(0, 255) || "download";
}
