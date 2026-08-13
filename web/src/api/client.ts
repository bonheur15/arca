import type {
  AccessRequest,
  AccessRequestReceipt,
  ApiToken,
  ArcaNode,
  AuditEvent,
  BootstrapStatus,
  FileVersion,
  InstanceSettings,
  Job,
  NodePage,
  Policy,
  PublicBundle,
  PublicShare,
  Session,
  Share,
  StorageOverview,
  User,
  UserPreferences,
} from "./types";

type JsonRecord = Record<string, unknown>;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly fieldErrors: Record<string, string[]>;
  readonly retryAfter: number | null;

  constructor(options: {
    status: number;
    code: string;
    message: string;
    requestId?: string | null;
    fieldErrors?: Record<string, string[]>;
    retryAfter?: number | null;
  }) {
    super(options.message);
    this.name = "ApiError";
    this.status = options.status;
    this.code = options.code;
    this.requestId = options.requestId ?? null;
    this.fieldErrors = options.fieldErrors ?? {};
    this.retryAfter = options.retryAfter ?? null;
  }
}

function object(value: unknown): JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

function unwrap(value: unknown): unknown {
  const record = object(value);
  return "data" in record ? record.data : value;
}

function valueAt(record: JsonRecord, ...keys: string[]): unknown {
  for (const key of keys) {
    if (key in record) return record[key];
  }
  return undefined;
}

function stringAt(record: JsonRecord, fallback: string, ...keys: string[]): string {
  const value = valueAt(record, ...keys);
  return typeof value === "string" ? value : fallback;
}

function nullableStringAt(record: JsonRecord, ...keys: string[]): string | null {
  const value = valueAt(record, ...keys);
  return typeof value === "string" ? value : null;
}

function numberAt(record: JsonRecord, fallback: number, ...keys: string[]): number {
  const value = valueAt(record, ...keys);
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function booleanAt(record: JsonRecord, fallback: boolean, ...keys: string[]): boolean {
  const value = valueAt(record, ...keys);
  return typeof value === "boolean" ? value : typeof value === "number" ? value !== 0 : fallback;
}

function arrayAt(record: JsonRecord, ...keys: string[]): unknown[] {
  const value = valueAt(record, ...keys);
  return Array.isArray(value) ? value : [];
}

function parseOwner(value: unknown) {
  const record = object(value);
  return {
    id: stringAt(record, "", "id"),
    username: stringAt(record, "", "username"),
    displayName: nullableStringAt(record, "displayName", "display_name"),
  };
}

export function parseNode(value: unknown): ArcaNode {
  const record = object(value);
  const capabilities = object(valueAt(record, "capabilities"));
  const ownerValue = valueAt(record, "owner");
  const fallbackOwner = {
    id: stringAt(record, "", "ownerId", "owner_id"),
    username: stringAt(record, "", "ownerUsername", "owner_username"),
    displayName: null,
  };
  return {
    id: stringAt(record, "", "id"),
    parentId: nullableStringAt(record, "parentId", "parent_id"),
    owner: ownerValue ? parseOwner(ownerValue) : fallbackOwner,
    kind: stringAt(record, "file", "kind") === "folder" ? "folder" : "file",
    name: stringAt(record, "Untitled", "name"),
    mimeType: nullableStringAt(record, "mimeType", "mime_type"),
    sizeBytes: numberAt(record, 0, "sizeBytes", "size_bytes", "size"),
    revision: numberAt(record, 1, "revision"),
    currentVersionId: nullableStringAt(record, "currentVersionId", "current_version_id"),
    shared: booleanAt(record, false, "shared", "isShared", "is_shared"),
    favorite: booleanAt(record, false, "favorite", "starred", "isFavorite", "is_favorite"),
    trashedAt: nullableStringAt(record, "trashedAt", "trashed_at"),
    createdAt: stringAt(record, new Date(0).toISOString(), "createdAt", "created_at"),
    updatedAt: stringAt(record, new Date(0).toISOString(), "updatedAt", "updated_at"),
    capabilities: {
      read: booleanAt(capabilities, true, "read"),
      write: booleanAt(capabilities, false, "write"),
      share: booleanAt(capabilities, false, "share"),
      trash: booleanAt(capabilities, false, "trash"),
      purge: booleanAt(capabilities, false, "purge"),
    },
  };
}

function parsePreferences(value: unknown): UserPreferences {
  const record = object(value);
  const theme = stringAt(record, "system", "themeMode", "theme_mode");
  const density = stringAt(record, "comfortable", "density");
  const accent = stringAt(record, "violet", "accent");
  const allowedAccents = ["violet", "indigo", "blue", "teal", "green", "amber", "orange", "rose"] as const;
  return {
    themeMode: theme === "light" || theme === "dark" ? theme : "system",
    accent: allowedAccents.find((candidate) => candidate === accent) ?? "violet",
    density: density === "compact" ? "compact" : "comfortable",
    reducedMotion: booleanAt(record, false, "reducedMotion", "reduced_motion"),
  };
}

export function parseUser(value: unknown): User {
  const record = object(value);
  const quota = object(valueAt(record, "quota"));
  const role = stringAt(record, "member", "role");
  const state = stringAt(record, "active", "state") as User["state"];
  return {
    id: stringAt(record, "", "id"),
    username: stringAt(record, "", "username"),
    email: stringAt(record, "", "email"),
    displayName: nullableStringAt(record, "displayName", "display_name"),
    role: role === "superadmin" ? "superadmin" : "member",
    state,
    quota: {
      usedBytes: numberAt(quota, numberAt(record, 0, "usedBytes", "used_bytes"), "usedBytes", "used_bytes"),
      reservedBytes: numberAt(quota, numberAt(record, 0, "reservedBytes", "reserved_bytes"), "reservedBytes", "reserved_bytes"),
      trashBytes: numberAt(quota, 0, "trashBytes", "trash_bytes"),
      versionBytes: numberAt(quota, 0, "versionBytes", "version_bytes"),
      quotaBytes: numberAt(quota, numberAt(record, 0, "quotaBytes", "quota_bytes"), "quotaBytes", "quota_bytes", "totalBytes", "total_bytes"),
      unlimited: booleanAt(quota, booleanAt(record, false, "quotaUnlimited", "quota_unlimited"), "unlimited", "quotaUnlimited", "quota_unlimited"),
    },
    preferences: parsePreferences(valueAt(record, "preferences") ?? record),
    createdAt: stringAt(record, new Date(0).toISOString(), "createdAt", "created_at"),
    updatedAt: stringAt(record, new Date(0).toISOString(), "updatedAt", "updated_at"),
    lastSignInAt: nullableStringAt(record, "lastSignInAt", "last_sign_in_at"),
  };
}

function parseList<T>(value: unknown, parser: (entry: unknown) => T): T[] {
  const unwrapped = unwrap(value);
  if (Array.isArray(unwrapped)) return unwrapped.map(parser);
  const record = object(unwrapped);
  const entries = arrayAt(record, "items", "results", "users", "nodes", "requests", "events", "tokens", "jobs", "shares");
  return entries.map(parser);
}

function csrfToken(): string | null {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="arca-csrf"]');
  return meta?.content || null;
}

interface RequestOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
  rawBody?: BodyInit;
}

async function apiRequest(path: string, options: RequestOptions = {}): Promise<unknown> {
  const headers = new Headers(options.headers);
  const token = csrfToken();
  if (token && options.method && !["GET", "HEAD", "OPTIONS"].includes(options.method.toUpperCase())) {
    headers.set("X-CSRF-Token", token);
  }
  let body: BodyInit | undefined = options.rawBody;
  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(options.body);
  }
  headers.set("Accept", "application/json");
  const response = await fetch(`/api/v1${path}`, {
    ...options,
    headers,
    ...(body === undefined ? {} : { body }),
    credentials: "same-origin",
  });
  if (!response.ok) {
    let payload: unknown = {};
    try {
      payload = await response.json();
    } catch {
      // The generic status text remains safe when a proxy returns non-JSON.
    }
    const problem = object(payload);
    const rawFieldErrors = object(valueAt(problem, "field_errors", "fieldErrors"));
    const fieldErrors: Record<string, string[]> = {};
    for (const [field, messages] of Object.entries(rawFieldErrors)) {
      fieldErrors[field] = Array.isArray(messages)
        ? messages.filter((message): message is string => typeof message === "string")
        : typeof messages === "string"
          ? [messages]
          : [];
    }
    const retryHeader = response.headers.get("Retry-After");
    throw new ApiError({
      status: response.status,
      code: stringAt(problem, `http_${response.status}`, "code", "type"),
      message: stringAt(problem, response.statusText || "Request failed", "detail", "message", "title"),
      requestId: nullableStringAt(problem, "request_id", "requestId") ?? response.headers.get("X-Request-ID"),
      fieldErrors,
      retryAfter: retryHeader && /^\d+$/.test(retryHeader) ? Number(retryHeader) : null,
    });
  }
  if (response.status === 204 || response.headers.get("Content-Length") === "0") return null;
  const contentType = response.headers.get("Content-Type") ?? "";
  return contentType.includes("json") ? response.json() : response.text();
}

function queryString(values: Record<string, string | number | boolean | null | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

function parseSession(value: unknown): Session {
  const record = object(unwrap(value));
  const user = valueAt(record, "user");
  return {
    authenticated: booleanAt(record, Boolean(user), "authenticated"),
    user: user ? parseUser(user) : null,
    csrfToken: nullableStringAt(record, "csrfToken", "csrf_token"),
  };
}

function parseNodePage(value: unknown): NodePage {
  const unwrapped = unwrap(value);
  const record = object(unwrapped);
  const rawItems = Array.isArray(unwrapped) ? unwrapped : arrayAt(record, "items", "nodes", "results");
  return {
    items: rawItems.map(parseNode),
    breadcrumbs: arrayAt(record, "breadcrumbs").map((entry) => {
      const crumb = object(entry);
      return { id: nullableStringAt(crumb, "id"), name: stringAt(crumb, "Files", "name") };
    }),
    nextCursor: nullableStringAt(record, "nextCursor", "next_cursor"),
  };
}

function parseShare(value: unknown): Share {
  const record = object(value);
  return {
    id: stringAt(record, "", "id"),
    roots: arrayAt(record, "roots").map(parseNode),
    recipients: arrayAt(record, "recipients").map((entry) => {
      const recipient = object(entry);
      return {
        id: stringAt(recipient, "", "id"),
        username: stringAt(recipient, "", "username"),
        email: stringAt(recipient, "", "email"),
        displayName: nullableStringAt(recipient, "displayName", "display_name"),
      };
    }),
    permission: stringAt(record, "viewer", "permission") === "editor" ? "editor" : "viewer",
    allowEditorUploads: booleanAt(record, false, "allowEditorUploads", "allow_editor_uploads"),
    editorAllowanceBytes: valueAt(record, "editorAllowanceBytes", "editor_allowance_bytes") === null
      ? null
      : numberAt(record, 0, "editorAllowanceBytes", "editor_allowance_bytes"),
    expiresAt: nullableStringAt(record, "expiresAt", "expires_at"),
    revokedAt: nullableStringAt(record, "revokedAt", "revoked_at"),
    createdAt: stringAt(record, new Date(0).toISOString(), "createdAt", "created_at"),
  };
}

function parsePublicShare(value: unknown): PublicShare {
  const record = object(unwrap(value));
  const result: PublicShare = {
    id: stringAt(record, "", "id"),
    roots: arrayAt(record, "roots").map(parseNode),
    expiresAt: stringAt(record, "", "expiresAt", "expires_at"),
    redemptionLimit: numberAt(record, 3, "redemptionLimit", "redemption_limit"),
    redemptionCount: numberAt(record, 0, "redemptionCount", "redemption_count"),
    state: stringAt(record, "active", "state") as PublicShare["state"],
  };
  const code = nullableStringAt(record, "code");
  return code ? { ...result, code } : result;
}

export const api = {
  async bootstrapStatus(): Promise<BootstrapStatus> {
    const record = object(unwrap(await apiRequest("/bootstrap/status")));
    const initialized = booleanAt(record, false, "initialized");
    return {
      initialized,
      instanceName: stringAt(record, "Arca", "instanceName", "instance_name", "name"),
      publicUrl: nullableStringAt(record, "publicUrl", "public_url"),
      setupRequired: booleanAt(record, !initialized, "setupRequired", "setup_required"),
      setupExpiresAt: nullableStringAt(record, "setupExpiresAt", "setup_expires_at"),
      allowAccessRequests: booleanAt(record, true, "allowAccessRequests", "allow_access_requests"),
    };
  },

  validateSetupCode: (code: string) => apiRequest("/bootstrap/validate", { method: "POST", body: { code } }),
  setupStart: (input: JsonRecord) => apiRequest("/bootstrap/start", { method: "POST", body: input }),
  setupVerify: (input: JsonRecord) => apiRequest("/bootstrap/verify", { method: "POST", body: input }),

  session: async () => parseSession(await apiRequest("/session")),
  startMagicAuth: (email: string) => apiRequest("/auth/magic/start", { method: "POST", body: { email } }),
  verifyMagicAuth: async (code: string) => parseSession(await apiRequest("/auth/magic/verify", { method: "POST", body: { code } })),
  logout: () => apiRequest("/auth/logout", { method: "POST" }),

  async requestAccess(input: { username: string; email: string; displayName?: string; reason?: string; website?: string; startedAt: number }): Promise<AccessRequestReceipt> {
    const record = object(unwrap(await apiRequest("/access-requests", { method: "POST", body: input })));
    return {
      statusToken: stringAt(record, "", "statusToken", "status_token"),
      state: stringAt(record, "pending", "state") as AccessRequestReceipt["state"],
    };
  },
  async accessRequestStatus(token: string): Promise<AccessRequestReceipt> {
    const record = object(unwrap(await apiRequest(`/access-requests/status${queryString({ token })}`)));
    return {
      statusToken: token,
      state: stringAt(record, "pending", "state") as AccessRequestReceipt["state"],
    };
  },

  async nodes(input: { parentId?: string; cursor?: string; sort?: string; order?: string; limit?: number } = {}): Promise<NodePage> {
    return parseNodePage(await apiRequest(`/nodes${queryString({
      parent_id: input.parentId,
      cursor: input.cursor,
      sort: input.sort,
      order: input.order,
      limit: input.limit ?? 100,
    })}`));
  },
  async collection(kind: "recent" | "favorites" | "trash" | "shared", query?: string): Promise<NodePage> {
    return parseNodePage(await apiRequest(`/${kind}${queryString({ q: query, limit: 100 })}`));
  },
  async search(query: string): Promise<NodePage> {
    return parseNodePage(await apiRequest(`/search${queryString({ q: query, limit: 100 })}`));
  },
  createFolder: async (input: { parentId: string | null; name: string }) => parseNode(unwrap(await apiRequest("/folders", { method: "POST", body: input }))),
  renameNode: async (id: string, name: string, revision: number) => parseNode(unwrap(await apiRequest(`/nodes/${id}`, { method: "PATCH", headers: { "If-Match": `\"${revision}\"` }, body: { name } }))),
  moveNode: (id: string, parentId: string | null, revision: number) => apiRequest(`/nodes/${id}/move`, { method: "POST", headers: { "If-Match": `\"${revision}\"`, "Idempotency-Key": crypto.randomUUID() }, body: { parentId } }),
  trashNode: (id: string, revision: number) => apiRequest(`/nodes/${id}/trash`, { method: "POST", headers: { "If-Match": `\"${revision}\"`, "Idempotency-Key": crypto.randomUUID() } }),
  restoreNode: (id: string, revision: number) => apiRequest(`/nodes/${id}/restore`, { method: "POST", headers: { "If-Match": `\"${revision}\"`, "Idempotency-Key": crypto.randomUUID() } }),
  purgeNode: (id: string, revision: number) => apiRequest(`/nodes/${id}/purge`, { method: "POST", headers: { "If-Match": `\"${revision}\"`, "Idempotency-Key": crypto.randomUUID() } }),
  favoriteNode: (id: string, favorite: boolean) => apiRequest(`/favorites/${id}`, { method: favorite ? "PUT" : "DELETE" }),
  async versions(id: string): Promise<FileVersion[]> {
    return parseList(await apiRequest(`/files/${id}/versions`), (entry) => {
      const record = object(entry);
      return {
        id: stringAt(record, "", "id"),
        sequence: numberAt(record, 1, "sequence"),
        sizeBytes: numberAt(record, 0, "sizeBytes", "size_bytes"),
        sha256: stringAt(record, "", "sha256"),
        mimeType: stringAt(record, "application/octet-stream", "mimeType", "mime_type"),
        creator: parseOwner(valueAt(record, "creator")),
        createdAt: stringAt(record, "", "createdAt", "created_at"),
      };
    });
  },

  async shares(): Promise<Share[]> {
    return parseList(await apiRequest("/shares"), parseShare);
  },
  createShare: async (input: JsonRecord) => parseShare(unwrap(await apiRequest("/shares", { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() }, body: input }))),
  revokeShare: (id: string) => apiRequest(`/shares/${id}`, { method: "DELETE" }),
  async createPublicShare(input: { rootIds: string[]; ttlMinutes: number; redemptionLimit: number }): Promise<PublicShare> {
    return parsePublicShare(await apiRequest("/public-shares", { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() }, body: input }));
  },
  async publicShares(): Promise<PublicShare[]> {
    return parseList(await apiRequest("/public-shares"), parsePublicShare);
  },
  revokePublicShare: (id: string) => apiRequest(`/public-shares/${id}`, { method: "DELETE" }),
  publicExchange: (code: string) => apiRequest("/public/exchange", { method: "POST", body: { code } }),
  async publicBundle(): Promise<PublicBundle> {
    const record = object(unwrap(await apiRequest("/public/bundle")));
    return {
      name: stringAt(record, "Shared bundle", "name"),
      expiresAt: stringAt(record, "", "expiresAt", "expires_at"),
      roots: arrayAt(record, "roots").map(parseNode),
      items: arrayAt(record, "items", "nodes").map(parseNode),
    };
  },

  async me(): Promise<User> { return parseUser(unwrap(await apiRequest("/me"))); },
  async updatePreferences(preferences: UserPreferences): Promise<UserPreferences> {
    return parsePreferences(unwrap(await apiRequest("/me/preferences", { method: "PUT", body: preferences })));
  },
  updateProfile: async (input: { displayName: string }) => parseUser(unwrap(await apiRequest("/me", { method: "PATCH", body: input }))),

  async tokens(): Promise<ApiToken[]> {
    return parseList(await apiRequest("/tokens"), (entry) => {
      const record = object(entry);
      const token: ApiToken = {
        id: stringAt(record, "", "id"),
        name: stringAt(record, "Untitled token", "name"),
        prefix: stringAt(record, "arca_pat_…", "prefix", "tokenPrefix", "token_prefix"),
        scopes: arrayAt(record, "scopes").filter((scope): scope is string => typeof scope === "string"),
        expiresAt: nullableStringAt(record, "expiresAt", "expires_at"),
        lastUsedAt: nullableStringAt(record, "lastUsedAt", "last_used_at"),
        createdAt: stringAt(record, "", "createdAt", "created_at"),
      };
      const plaintext = nullableStringAt(record, "token");
      return plaintext ? { ...token, token: plaintext } : token;
    });
  },
  createToken: async (input: { name: string; scopes: string[]; expiresAt: string | null }): Promise<ApiToken> => {
    const records = await api.tokensFrom(await apiRequest("/tokens", { method: "POST", body: input }));
    const first = records[0];
    if (!first) throw new ApiError({ status: 502, code: "invalid_response", message: "The server returned an invalid token response." });
    return first;
  },
  tokensFrom: async (payload: unknown): Promise<ApiToken[]> => {
    const value = unwrap(payload);
    const record = object(value);
    const source = Array.isArray(value) ? value : "id" in record ? [record] : arrayAt(record, "items", "tokens");
    return source.map((entry) => {
      const item = object(entry);
      const token: ApiToken = {
        id: stringAt(item, "", "id"),
        name: stringAt(item, "Untitled token", "name"),
        prefix: stringAt(item, "arca_pat_…", "prefix", "tokenPrefix", "token_prefix"),
        scopes: arrayAt(item, "scopes").filter((scope): scope is string => typeof scope === "string"),
        expiresAt: nullableStringAt(item, "expiresAt", "expires_at"),
        lastUsedAt: nullableStringAt(item, "lastUsedAt", "last_used_at"),
        createdAt: stringAt(item, "", "createdAt", "created_at"),
      };
      const plaintext = nullableStringAt(item, "token");
      return plaintext ? { ...token, token: plaintext } : token;
    });
  },
  revokeToken: (id: string) => apiRequest(`/tokens/${id}`, { method: "DELETE" }),

  async adminUsers(): Promise<User[]> { return parseList(await apiRequest("/admin/users"), parseUser); },
  async adminRequests(): Promise<AccessRequest[]> {
    return parseList(await apiRequest("/admin/requests"), (entry) => {
      const record = object(entry);
      return {
        id: stringAt(record, "", "id"),
        username: stringAt(record, "", "username"),
        email: stringAt(record, "", "email"),
        displayName: nullableStringAt(record, "displayName", "display_name"),
        reason: nullableStringAt(record, "reason"),
        state: stringAt(record, "pending", "state") as AccessRequest["state"],
        requestedAt: stringAt(record, "", "requestedAt", "requested_at"),
      };
    });
  },
  decideRequest: (id: string, input: JsonRecord) => apiRequest(`/admin/requests/${id}`, { method: "POST", body: input }),
  updateUser: async (id: string, input: JsonRecord) => parseUser(unwrap(await apiRequest(`/admin/users/${id}`, { method: "PATCH", body: input }))),
  async storageOverview(): Promise<StorageOverview> {
    const record = object(unwrap(await apiRequest("/admin/storage")));
    return {
      totalBytes: numberAt(record, 0, "totalBytes", "total_bytes"),
      availableBytes: numberAt(record, 0, "availableBytes", "available_bytes"),
      usedBytes: numberAt(record, 0, "usedBytes", "used_bytes"),
      reservedBytes: numberAt(record, 0, "reservedBytes", "reserved_bytes"),
      trashBytes: numberAt(record, 0, "trashBytes", "trash_bytes"),
      versionBytes: numberAt(record, 0, "versionBytes", "version_bytes"),
      blobCount: numberAt(record, 0, "blobCount", "blob_count"),
      orphanCount: numberAt(record, 0, "orphanCount", "orphan_count"),
      walBytes: numberAt(record, 0, "walBytes", "wal_bytes"),
      failedJobs: numberAt(record, 0, "failedJobs", "failed_jobs"),
      lastBackupAt: nullableStringAt(record, "lastBackupAt", "last_backup_at"),
    };
  },
  async auditEvents(): Promise<AuditEvent[]> {
    return parseList(await apiRequest("/admin/audit"), (entry) => {
      const record = object(entry);
      const actor = valueAt(record, "actor");
      return {
        id: stringAt(record, "", "id"),
        action: stringAt(record, "unknown", "action"),
        actor: actor ? parseOwner(actor) : null,
        targetType: nullableStringAt(record, "targetType", "target_type"),
        targetId: nullableStringAt(record, "targetId", "target_id"),
        summary: stringAt(record, "Activity recorded", "summary"),
        ipAddress: nullableStringAt(record, "ipAddress", "ip_address"),
        createdAt: stringAt(record, "", "createdAt", "created_at"),
      };
    });
  },
  async jobs(): Promise<Job[]> {
    return parseList(await apiRequest("/admin/jobs"), (entry) => {
      const record = object(entry);
      return {
        id: stringAt(record, "", "id"),
        kind: stringAt(record, "unknown", "kind"),
        state: stringAt(record, "pending", "state") as Job["state"],
        attempts: numberAt(record, 0, "attempts"),
        lastError: nullableStringAt(record, "lastError", "last_error"),
        nextRunAt: nullableStringAt(record, "nextRunAt", "next_run_at"),
        createdAt: stringAt(record, "", "createdAt", "created_at"),
      };
    });
  },
  retryJob: (id: string) => apiRequest(`/admin/jobs/${id}/retry`, { method: "POST" }),
  async settings(): Promise<InstanceSettings> {
    const record = object(unwrap(await apiRequest("/admin/settings")));
    return {
      instanceName: stringAt(record, "Arca", "instanceName", "instance_name", "name"),
      publicUrl: stringAt(record, "", "publicUrl", "public_url"),
      allowAccessRequests: booleanAt(record, true, "allowAccessRequests", "allow_access_requests"),
      filesystemReserveBytes: numberAt(record, 1_073_741_824, "filesystemReserveBytes", "filesystem_reserve_bytes"),
      trustedProxyCidrs: arrayAt(record, "trustedProxyCidrs", "trusted_proxy_cidrs").filter((item): item is string => typeof item === "string"),
    };
  },
  saveSettings: (input: InstanceSettings) => apiRequest("/admin/settings", { method: "PUT", body: input }),
  async policy(userId: string): Promise<Policy> {
    const record = object(unwrap(await apiRequest(`/admin/policies/${userId}`)));
    return {
      quotaBytes: numberAt(record, 0, "quotaBytes", "quota_bytes"),
      unlimited: booleanAt(record, false, "unlimited", "quotaUnlimited", "quota_unlimited"),
      maxFileBytes: valueAt(record, "maxFileBytes", "max_file_bytes") === null ? null : numberAt(record, 0, "maxFileBytes", "max_file_bytes"),
      maxItems: numberAt(record, 100000, "maxItems", "max_items"),
      allowInternalSharing: booleanAt(record, true, "allowInternalSharing", "allow_internal_sharing"),
      allowPublicSharing: booleanAt(record, true, "allowPublicSharing", "allow_public_sharing"),
      allowApiTokens: booleanAt(record, true, "allowApiTokens", "allow_api_tokens"),
      maxConcurrentUploads: numberAt(record, 3, "maxConcurrentUploads", "max_concurrent_uploads"),
      maxPendingUploads: numberAt(record, 20, "maxPendingUploads", "max_pending_uploads"),
      maxActivePublicShares: numberAt(record, 10, "maxActivePublicShares", "max_active_public_shares"),
      maxPublicTtlMinutes: numberAt(record, 30, "maxPublicTtlMinutes", "max_public_ttl_minutes"),
      maxPublicRedemptions: numberAt(record, 10, "maxPublicRedemptions", "max_public_redemptions"),
      blockedExtensions: arrayAt(record, "blockedExtensions", "blocked_extensions").filter((item): item is string => typeof item === "string"),
    };
  },
  savePolicy: (userId: string, input: Policy) => apiRequest(`/admin/policies/${userId}`, { method: "PUT", body: input }),
};

export function describeError(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof TypeError) return "Arca could not reach the server. Check your connection and try again.";
  if (error instanceof Error) return error.message;
  return "Something unexpected happened.";
}
