import { afterEach, describe, expect, it, vi } from "vitest";
import { api, parseNode, parseUser } from "./client";

afterEach(() => vi.restoreAllMocks());

function jsonResponse(value: unknown = {}): Response {
  return new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("API boundary parsing", () => {
  it("accepts snake_case node responses without trusting absent capabilities", () => {
    const node = parseNode({
      id: "node-1",
      owner_id: "user-1",
      kind: "folder",
      name: "Research",
      size_bytes: 42,
      current_version_id: null,
      is_shared: 1,
      updated_at: "2026-08-14T10:00:00Z",
      capabilities: { read: true, write: true, share: true, trash: true },
    });

    expect(node).toMatchObject({
      id: "node-1",
      kind: "folder",
      name: "Research",
      shared: true,
      owner: { id: "user-1" },
      capabilities: { read: true, write: true, share: true, trash: true, purge: false },
    });
  });

  it("normalizes embedded quota and appearance preferences", () => {
    const user = parseUser({
      id: "user-1",
      username: "ada",
      email: "ada@example.com",
      role: "superadmin",
      state: "active",
      quota: { used_bytes: 1024, quota_bytes: 4096, unlimited: false },
      preferences: { theme_mode: "dark", accent: "teal", density: "compact", reduced_motion: 1 },
    });

    expect(user.role).toBe("superadmin");
    expect(user.quota).toMatchObject({ usedBytes: 1024, quotaBytes: 4096 });
    expect(user.preferences).toEqual({ themeMode: "dark", accent: "teal", density: "compact", reducedMotion: true });
  });

  it("sends the audited support target when listing a folder", async () => {
    const request = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ items: [] }));

    await api.nodes({ parentId: "folder 1", supportUserId: "user-019" });

    expect(request).toHaveBeenCalledOnce();
    expect(request.mock.calls[0]?.[0]).toBe("/api/v1/nodes?parent_id=folder+1&support_user=user-019&limit=100");
  });

  it("uses the explicit save-copy payload for shared files", async () => {
    const request = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse());

    await api.saveCopyNode("source-1", { destinationId: null, name: "Research.pdf", conflictMode: "keep_both" });

    const [, init] = request.mock.calls[0] ?? [];
    expect(request.mock.calls[0]?.[0]).toBe("/api/v1/nodes/source-1/save-copy");
    expect(init).toMatchObject({ method: "POST", credentials: "same-origin" });
    expect(JSON.parse(String(init?.body))).toEqual({ destinationId: null, name: "Research.pdf", conflictMode: "keep_both" });
    expect(new Headers(init?.headers).get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it("reads explicit CORS origins from instance settings", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({
      instanceName: "Arca",
      publicUrl: "https://arca.example.com",
      allowedCorsOrigins: ["https://app.example.com"],
    }));

    const settings = await api.settings();

    expect(settings.allowedCorsOrigins).toEqual(["https://app.example.com"]);
  });

  it("normalizes MIME and transfer limits in user policy responses", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({
      quotaBytes: 10_000,
      maxItems: 100,
      maxConcurrentUploads: 3,
      maxPendingUploads: 20,
      maxPublicTtlMinutes: 10,
      maxPublicRedemptions: 3,
      allowedMimeGroups: ["image", "application"],
      uploadRateBytes: 2_097_152,
      downloadRateBytes: null,
    }));

    const policy = await api.policy("user-019");

    expect(policy.allowedMimeGroups).toEqual(["image", "application"]);
    expect(policy.uploadRateBytes).toBe(2_097_152);
    expect(policy.downloadRateBytes).toBeNull();
  });
});
