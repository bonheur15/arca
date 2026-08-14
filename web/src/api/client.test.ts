import { describe, expect, it } from "vitest";
import { parseNode, parseUser } from "./client";

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
});
