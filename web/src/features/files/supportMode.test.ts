import { describe, expect, it } from "vitest";
import { normalizeSupportUser, supportSearch, supportUserFromLocation } from "./supportMode";

describe("audited support mode", () => {
  it("normalizes and preserves an opaque support user identifier", () => {
    expect(normalizeSupportUser("  user-019  ")).toBe("user-019");
    expect(supportSearch("user-019")).toEqual({ support_user: "user-019" });
    expect(supportSearch(null)).toEqual({});
  });

  it("is active only while browsing file routes", () => {
    const search = { support_user: "user-019" };
    expect(supportUserFromLocation("/files", search)).toBe("user-019");
    expect(supportUserFromLocation("/files/folder-1", search)).toBe("user-019");
    expect(supportUserFromLocation("/admin/users", search)).toBeNull();
  });
});
