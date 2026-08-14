export type Role = "superadmin" | "member";
export type AccountState =
  | "provisioning"
  | "active"
  | "suspended"
  | "over_quota"
  | "deletion_pending"
  | "deleted";

export type ThemeMode = "system" | "light" | "dark";
export type Density = "comfortable" | "compact";
export type Accent = "violet" | "indigo" | "blue" | "cyan" | "teal" | "green" | "amber" | "rose";

export interface QuotaSummary {
  usedBytes: number;
  reservedBytes: number;
  trashBytes: number;
  versionBytes: number;
  quotaBytes: number;
  unlimited: boolean;
}

export interface UserPreferences {
  themeMode: ThemeMode;
  accent: Accent;
  density: Density;
  reducedMotion: boolean;
}

export interface User {
  id: string;
  username: string;
  email: string;
  displayName: string | null;
  role: Role;
  state: AccountState;
  quota: QuotaSummary;
  preferences: UserPreferences;
  createdAt: string;
  updatedAt: string;
  lastSignInAt: string | null;
  deletionDueAt: string | null;
}

export interface Session {
  authenticated: boolean;
  user: User | null;
  csrfToken: string | null;
}

export interface SessionRecord {
  id: string;
  userAgent: string;
  ipAddress: string | null;
  current: boolean;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string | null;
}

export interface BootstrapStatus {
  initialized: boolean;
  instanceName: string;
  publicUrl: string | null;
  setupRequired: boolean;
  setupExpiresAt: string | null;
  allowAccessRequests: boolean;
}

export interface NodeOwner {
  id: string;
  username: string;
  displayName: string | null;
}

export type NodeKind = "file" | "folder";

export interface NodeCapabilities {
  read: boolean;
  write: boolean;
  share: boolean;
  trash: boolean;
  purge: boolean;
}

export interface ArcaNode {
  id: string;
  parentId: string | null;
  owner: NodeOwner;
  kind: NodeKind;
  name: string;
  mimeType: string | null;
  sizeBytes: number;
  revision: number;
  currentVersionId: string | null;
  shared: boolean;
  favorite: boolean;
  trashedAt: string | null;
  createdAt: string;
  updatedAt: string;
  capabilities: NodeCapabilities;
}

export interface FileVersion {
  id: string;
  sequence: number;
  sizeBytes: number;
  sha256: string;
  mimeType: string;
  creator: NodeOwner;
  createdAt: string;
}

export interface BreadcrumbItem {
  id: string | null;
  name: string;
}

export interface NodePage {
  items: ArcaNode[];
  breadcrumbs: BreadcrumbItem[];
  nextCursor: string | null;
}

export type UploadState =
  | "queued"
  | "uploading"
  | "paused"
  | "retrying"
  | "conflict"
  | "finalizing"
  | "completed"
  | "failed"
  | "cancelled";

export interface UploadItem {
  id: string;
  name: string;
  size: number;
  offset: number;
  progress: number;
  state: UploadState;
  error?: string | undefined;
}

export type SharePermission = "viewer" | "editor";

export interface ShareRecipient {
  id: string;
  username: string;
  email: string;
  displayName: string | null;
}

export interface Share {
  id: string;
  ownerId: string;
  roots: ArcaNode[];
  recipients: ShareRecipient[];
  permission: SharePermission;
  allowEditorUploads: boolean;
  editorAllowanceBytes: number | null;
  expiresAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

export interface PublicShare {
  id: string;
  roots: ArcaNode[];
  expiresAt: string;
  redemptionLimit: number;
  redemptionCount: number;
  state: "active" | "expired" | "exhausted" | "revoked";
  code?: string;
}

export interface PublicBundle {
  name: string;
  expiresAt: string;
  roots: ArcaNode[];
  items: ArcaNode[];
}

export interface AccessRequestReceipt {
  statusToken: string;
  state: "pending" | "approved" | "rejected";
}

export interface AccessRequest {
  id: string;
  username: string;
  email: string;
  displayName: string | null;
  reason: string | null;
  state: "pending" | "approved" | "rejected";
  requestedAt: string;
}

export interface ApiToken {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
  token?: string;
}

export interface StorageOverview {
  totalBytes: number;
  availableBytes: number;
  usedBytes: number;
  reservedBytes: number;
  trashBytes: number;
  versionBytes: number;
  blobCount: number;
  orphanCount: number;
  walBytes: number;
  failedJobs: number;
  lastBackupAt: string | null;
}

export interface AuditEvent {
  id: string;
  action: string;
  actor: NodeOwner | null;
  targetType: string | null;
  targetId: string | null;
  summary: string;
  ipAddress: string | null;
  createdAt: string;
}

export interface Job {
  id: string;
  kind: string;
  state: "pending" | "running" | "retrying" | "completed" | "dead";
  attempts: number;
  lastError: string | null;
  nextRunAt: string | null;
  createdAt: string;
}

export interface Notification {
  id: string;
  kind: string;
  payload: Record<string, unknown>;
  readAt: string | null;
  createdAt: string;
}

export interface InstanceSettings {
  instanceName: string;
  publicUrl: string;
  allowAccessRequests: boolean;
  filesystemReserveBytes: number;
  trustedProxyCidrs: string[];
  allowedCorsOrigins: string[];
}

export interface Policy {
  quotaBytes: number;
  unlimited: boolean;
  maxFileBytes: number | null;
  maxItems: number;
  allowInternalSharing: boolean;
  allowPublicSharing: boolean;
  allowApiTokens: boolean;
  maxConcurrentUploads: number;
  maxPendingUploads: number;
  maxActivePublicShares: number;
  maxPublicTtlMinutes: number;
  maxPublicRedemptions: number;
  blockedExtensions: string[];
  allowedMimeGroups: string[];
  uploadRateBytes: number | null;
  downloadRateBytes: number | null;
}
