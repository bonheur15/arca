export interface SupportRouteSearch {
  support_user?: string;
}

export function normalizeSupportUser(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized || undefined;
}

export function supportSearch(userId: string | null | undefined): SupportRouteSearch {
  const normalized = normalizeSupportUser(userId);
  return normalized ? { support_user: normalized } : {};
}

export function supportUserFromLocation(pathname: string, search: Record<string, unknown>): string | null {
  if (pathname !== "/files" && !pathname.startsWith("/files/")) return null;
  return normalizeSupportUser(search.support_user) ?? null;
}
