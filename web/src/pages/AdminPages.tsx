import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  Check,
  CircleGauge,
  Clock3,
  Database,
  FileClock,
  Gauge,
  HardDrive,
  KeyRound,
  LifeBuoy,
  Plus,
  RefreshCw,
  Server,
  Settings,
  ShieldCheck,
  UserCheck,
  UserRoundCog,
  Users,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { api, describeError } from "../api/client";
import type { AccessRequest, InstanceSettings, Policy, User } from "../api/types";
import { formatBytes, formatRelativeDate, initials } from "../lib";
import { Button, EmptyState, ErrorState, Field, IconButton, LoadingState, Modal, SkeletonRows, StatusPill } from "../components/Primitives";

const adminLinks = [
  { to: "/admin/users", label: "Users", icon: Users },
  { to: "/admin/requests", label: "Requests", icon: UserRoundCog },
  { to: "/admin/storage", label: "Storage & jobs", icon: HardDrive },
  { to: "/admin/policies", label: "Policies", icon: ShieldCheck },
  { to: "/admin/audit", label: "Audit log", icon: FileClock },
  { to: "/admin/settings", label: "Instance", icon: Gauge },
];

function AdminLayout({ title, description, action, children }: { title: string; description: string; action?: ReactNode; children: ReactNode }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  return (
    <div className="admin-layout">
      <div className="admin-tabs" role="navigation" aria-label="Administration">{adminLinks.map((item) => { const Icon = item.icon; return <Link className={pathname === item.to ? "active" : ""} key={item.to} to={item.to}><Icon size={16} />{item.label}</Link>; })}</div>
      <div className="page-title-row"><div className="page-heading"><span className="eyebrow">Administration</span><h1>{title}</h1><p>{description}</p></div>{action}</div>
      {children}
    </div>
  );
}

function stateTone(state: User["state"]): "success" | "warning" | "danger" | "neutral" {
  if (state === "active") return "success";
  if (state === "over_quota" || state === "provisioning") return "warning";
  if (state === "suspended" || state === "deletion_pending") return "danger";
  return "neutral";
}

function CreateUserDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ username: "", email: "", displayName: "", role: "member", quotaGb: 50 });
  const create = useMutation({ mutationFn: () => api.createUser({ ...form, displayName: form.displayName || null, quotaBytes: form.quotaGb * 1024 ** 3 }), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["admin-users"] }); onClose(); } });
  return <Modal open={open} onOpenChange={(value) => { if (!value) onClose(); }} title="Create an account" description="Provision the identity without sending an invitation. The user signs in later with Magic Auth."><form className="dialog-form" onSubmit={(event) => { event.preventDefault(); create.mutate(); }}><div className="form-grid"><Field label="Username"><input autoFocus minLength={3} onChange={(event) => setForm({ ...form, username: event.target.value })} required value={form.username} /></Field><Field label="Email"><input onChange={(event) => setForm({ ...form, email: event.target.value })} required type="email" value={form.email} /></Field><Field label="Display name"><input onChange={(event) => setForm({ ...form, displayName: event.target.value })} value={form.displayName} /></Field><Field label="Role"><select onChange={(event) => setForm({ ...form, role: event.target.value })} value={form.role}><option value="member">Member</option><option value="superadmin">Superadmin</option></select></Field><Field label="Storage quota"><div className="input-suffix"><input min={1} onChange={(event) => setForm({ ...form, quotaGb: Number(event.target.value) })} type="number" value={form.quotaGb} /><span>GB</span></div></Field></div>{create.error ? <p className="form-error">{describeError(create.error)}</p> : null}<div className="dialog-actions"><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button disabled={create.isPending}>{create.isPending ? "Provisioning…" : "Create account"}</Button></div></form></Modal>;
}

function UserDialog({ user, onClose }: { user: User | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [quotaGb, setQuotaGb] = useState(user ? Math.max(1, Math.round(user.quota.quotaBytes / 1024 ** 3)) : 50);
  const [role, setRole] = useState(user?.role ?? "member");
  const [supportReason, setSupportReason] = useState("");
  useEffect(() => { if (user) { setQuotaGb(Math.max(1, Math.round(user.quota.quotaBytes / 1024 ** 3))); setRole(user.role); } }, [user]);
  const update = useMutation({ mutationFn: (input: Record<string, unknown>) => api.updateUser(user?.id ?? "", input), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["admin-users"] }); onClose(); } });
  const support = useMutation({ mutationFn: () => api.startSupportAccess(user?.id ?? "", supportReason), onSuccess: () => { window.location.assign(`/files?support_user=${user?.id ?? ""}`); } });
  if (!user) return null;
  const suspendAction = user.state === "suspended" ? "activate" : "suspend";
  return (
    <Modal open onOpenChange={(open) => { if (!open) onClose(); }} title={user.displayName || user.username} description={`${user.email} · @${user.username}`} wide>
      <div className="user-admin-summary"><span className="avatar avatar--large">{initials(user.displayName || user.username)}</span><div><StatusPill tone={stateTone(user.state)}>{user.state.replace("_", " ")}</StatusPill><StatusPill tone={user.role === "superadmin" ? "accent" : "neutral"}>{user.role}</StatusPill></div></div>
      <div className="admin-dialog-grid">
        <section><h3>Account controls</h3><Field label="Role"><select onChange={(event) => setRole(event.target.value as User["role"])} value={role}><option value="member">Member</option><option value="superadmin">Superadmin</option></select></Field><Field label="Storage quota"><div className="input-suffix"><input min={1} onChange={(event) => setQuotaGb(Number(event.target.value))} type="number" value={quotaGb} /><span>GB</span></div></Field><div className="dialog-actions dialog-actions--start"><Button disabled={update.isPending} onClick={() => update.mutate({ role, quotaBytes: quotaGb * 1024 ** 3 })}>Save controls</Button><Button disabled={update.isPending} onClick={() => update.mutate({ action: suspendAction })} variant={suspendAction === "suspend" ? "danger" : "secondary"}>{suspendAction === "suspend" ? "Suspend account" : "Restore account"}</Button></div></section>
        <section><h3>Audited support access</h3><p className="muted">Open this user’s files read-only for 15 minutes. Every opened item is recorded.</p><Field hint="Required, at least 10 characters" label="Reason"><textarea minLength={10} onChange={(event) => setSupportReason(event.target.value)} rows={3} value={supportReason} /></Field><Button disabled={supportReason.trim().length < 10 || support.isPending} onClick={() => support.mutate()} variant="secondary"><LifeBuoy size={16} />Begin support session</Button></section>
      </div>
      {update.error || support.error ? <p className="form-error">{describeError(update.error ?? support.error)}</p> : null}
    </Modal>
  );
}

export function AdminUsersPage() {
  const users = useQuery({ queryKey: ["admin-users"], queryFn: api.adminUsers });
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<User | null>(null);
  return (
    <AdminLayout title="People" description="Accounts, roles, quotas, and recovery for this Arca." action={<Button onClick={() => setCreateOpen(true)}><Plus size={17} />Create user</Button>}>
      {users.isPending ? <SkeletonRows /> : users.isError ? <ErrorState error={users.error} onRetry={() => void users.refetch()} /> : !users.data.length ? <EmptyState title="No accounts" description="Create the first member account when your team is ready." /> : <div className="admin-table"><div className="admin-table__head"><span>User</span><span>Role</span><span>Status</span><span>Storage</span><span>Last sign-in</span><span /></div>{users.data.map((user) => { const percent = user.quota.unlimited || !user.quota.quotaBytes ? 0 : Math.min(100, user.quota.usedBytes / user.quota.quotaBytes * 100); return <button className="admin-table__row" key={user.id} onClick={() => setSelected(user)} type="button"><span className="person-cell"><i className="avatar">{initials(user.displayName || user.username)}</i><span><strong>{user.displayName || user.username}</strong><small>{user.email}</small></span></span><span><StatusPill tone={user.role === "superadmin" ? "accent" : "neutral"}>{user.role}</StatusPill></span><span><StatusPill tone={stateTone(user.state)}>{user.state.replace("_", " ")}</StatusPill></span><span className="storage-cell"><span><i style={{ width: `${percent}%` }} /></span><small>{user.quota.unlimited ? `${formatBytes(user.quota.usedBytes)} used` : `${formatBytes(user.quota.usedBytes)} / ${formatBytes(user.quota.quotaBytes)}`}</small></span><span>{formatRelativeDate(user.lastSignInAt)}</span><span>View</span></button>; })}</div>}
      <CreateUserDialog onClose={() => setCreateOpen(false)} open={createOpen} />
      <UserDialog onClose={() => setSelected(null)} user={selected} />
    </AdminLayout>
  );
}

function RequestDecisionDialog({ request, decision, onClose }: { request: AccessRequest | null; decision: "approve" | "reject"; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState(request?.username ?? "");
  const [quotaGb, setQuotaGb] = useState(50);
  const [note, setNote] = useState("");
  useEffect(() => setUsername(request?.username ?? ""), [request]);
  const decide = useMutation({ mutationFn: () => api.decideRequest(request?.id ?? "", decision === "approve" ? { action: "approve", username, quotaBytes: quotaGb * 1024 ** 3 } : { action: "reject", note }), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["admin-requests"] }); onClose(); } });
  return <Modal open={Boolean(request)} onOpenChange={(open) => { if (!open) onClose(); }} title={decision === "approve" ? "Approve account request" : "Reject request"} description={request ? `${request.displayName || request.username} · ${request.email}` : ""}>{decision === "approve" ? <div className="dialog-form"><Field label="Username"><input autoFocus minLength={3} onChange={(event) => setUsername(event.target.value)} value={username} /></Field><Field label="Storage quota"><div className="input-suffix"><input min={1} onChange={(event) => setQuotaGb(Number(event.target.value))} type="number" value={quotaGb} /><span>GB</span></div></Field><div className="notice"><UserCheck size={18} /><p>Approval creates the WorkOS identity silently. The member signs in later with their normal Magic Auth code.</p></div></div> : <Field hint="Optional internal note" label="Reason"><textarea autoFocus onChange={(event) => setNote(event.target.value)} rows={3} value={note} /></Field>}{decide.error ? <p className="form-error">{describeError(decide.error)}</p> : null}<div className="dialog-actions"><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant={decision === "reject" ? "danger" : "primary"} disabled={decide.isPending || (decision === "approve" && !username.trim())} onClick={() => decide.mutate()}>{decide.isPending ? "Working…" : decision === "approve" ? "Approve account" : "Reject request"}</Button></div></Modal>;
}

export function AdminRequestsPage() {
  const requests = useQuery({ queryKey: ["admin-requests"], queryFn: api.adminRequests });
  const [decision, setDecision] = useState<{ request: AccessRequest; kind: "approve" | "reject" } | null>(null);
  return (
    <AdminLayout title="Access requests" description="Review people asking to join. Approval never sends an invitation email.">
      {requests.isPending ? <SkeletonRows /> : requests.isError ? <ErrorState error={requests.error} onRetry={() => void requests.refetch()} /> : !requests.data.length ? <EmptyState icon="success" title="You’re all caught up" description="New account requests will appear here." /> : <div className="request-list">{requests.data.map((request) => <article className="request-card" key={request.id}><div className="request-card__top"><span className="avatar">{initials(request.displayName || request.username)}</span><div><h3>{request.displayName || request.username}</h3><p>@{request.username} · {request.email}</p></div><StatusPill tone={request.state === "pending" ? "warning" : request.state === "approved" ? "success" : "neutral"}>{request.state}</StatusPill></div>{request.reason ? <blockquote>{request.reason}</blockquote> : <p className="muted">No note provided.</p>}<div className="request-card__foot"><span><Clock3 size={14} />Requested {formatRelativeDate(request.requestedAt)}</span>{request.state === "pending" ? <div><Button variant="ghost" onClick={() => setDecision({ request, kind: "reject" })}>Reject</Button><Button onClick={() => setDecision({ request, kind: "approve" })}>Review & approve</Button></div> : null}</div></article>)}</div>}
      <RequestDecisionDialog decision={decision?.kind ?? "approve"} onClose={() => setDecision(null)} request={decision?.request ?? null} />
    </AdminLayout>
  );
}

function MetricCard({ icon: Icon, label, value, note, tone }: { icon: typeof HardDrive; label: string; value: string; note: string; tone?: "warning" | undefined }) {
  return <article className={`metric-card ${tone ? `metric-card--${tone}` : ""}`}><span className="metric-card__icon"><Icon size={19} /></span><div><span>{label}</span><strong>{value}</strong><small>{note}</small></div></article>;
}

export function AdminStoragePage() {
  const queryClient = useQueryClient();
  const storage = useQuery({ queryKey: ["admin-storage"], queryFn: api.storageOverview, refetchInterval: 30_000 });
  const jobs = useQuery({ queryKey: ["admin-jobs"], queryFn: api.jobs, refetchInterval: 30_000 });
  const retry = useMutation({ mutationFn: api.retryJob, onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["admin-jobs"] }) });
  if (storage.isError) return <AdminLayout title="Storage & jobs" description="Filesystem capacity and background work."><ErrorState error={storage.error} onRetry={() => void storage.refetch()} /></AdminLayout>;
  const value = storage.data;
  const physicalPercent = value?.totalBytes ? Math.min(100, value.usedBytes / value.totalBytes * 100) : 0;
  return (
    <AdminLayout title="Storage & jobs" description="Watch disk headroom, durable metadata, cleanup, and repair work." action={<Button variant="secondary" onClick={() => { void storage.refetch(); void jobs.refetch(); }}><RefreshCw size={16} />Refresh</Button>}>
      {storage.isPending || !value ? <LoadingState label="Reading storage health…" /> : <><div className="metrics-grid"><MetricCard icon={HardDrive} label="Stored content" value={formatBytes(value.usedBytes)} note={`${Math.round(physicalPercent)}% of host filesystem`} /><MetricCard icon={Database} label="Available" value={formatBytes(value.availableBytes)} note="After filesystem reserve" tone={physicalPercent > 85 ? "warning" : undefined} /><MetricCard icon={CircleGauge} label="Reservations" value={formatBytes(value.reservedBytes)} note="In-flight uploads" /><MetricCard icon={FileClock} label="Recoverable" value={formatBytes(value.trashBytes + value.versionBytes)} note="Trash and history" /></div><section className="storage-visual"><div className="storage-visual__head"><div><h2>Filesystem capacity</h2><p>Arca stops accepting writes before the protected reserve is reached.</p></div><strong>{formatBytes(value.totalBytes)}</strong></div><div className="storage-bar"><span className="storage-bar__files" style={{ width: `${physicalPercent}%` }} /><span className="storage-bar__reserved" style={{ width: `${value.totalBytes ? value.reservedBytes / value.totalBytes * 100 : 0}%` }} /></div><div className="storage-legend"><span><i className="files" />Content</span><span><i className="reserved" />Reserved</span><span><i />Available</span></div><div className="storage-facts"><div><span>Immutable blobs</span><strong>{value.blobCount.toLocaleString()}</strong></div><div><span>Orphans</span><strong>{value.orphanCount.toLocaleString()}</strong></div><div><span>SQLite WAL</span><strong>{formatBytes(value.walBytes)}</strong></div><div><span>Last backup</span><strong>{formatRelativeDate(value.lastBackupAt)}</strong></div></div></section></>}
      <section className="jobs-section"><div className="settings-section__head"><h2>Background jobs</h2><p>Persistent work resumes after restarts and dead-letters after bounded retries.</p></div>{jobs.isPending ? <LoadingState compact label="Loading jobs…" /> : jobs.isError ? <ErrorState error={jobs.error} onRetry={() => void jobs.refetch()} /> : !jobs.data.length ? <EmptyState icon="success" title="No queued work" description="Cleanup, previews, and reconciliation are caught up." /> : <div className="job-list">{jobs.data.map((job) => <div className="job-row" key={job.id}><span className={`job-dot job-dot--${job.state}`} /><div><strong>{job.kind.replaceAll("_", " ")}</strong><span>{job.lastError ?? (job.nextRunAt ? `Next run ${formatRelativeDate(job.nextRunAt)}` : `Created ${formatRelativeDate(job.createdAt)}`)}</span></div><StatusPill tone={job.state === "dead" ? "danger" : job.state === "completed" ? "success" : "neutral"}>{job.state}</StatusPill>{job.state === "dead" ? <Button disabled={retry.isPending} onClick={() => retry.mutate(job.id)} variant="secondary">Retry</Button> : null}</div>)}</div>}</section>
    </AdminLayout>
  );
}

const defaultPolicy: Policy = { quotaBytes: 50 * 1024 ** 3, unlimited: false, maxFileBytes: null, maxItems: 100000, allowInternalSharing: true, allowPublicSharing: true, allowApiTokens: true, maxConcurrentUploads: 3, maxPendingUploads: 20, maxActivePublicShares: 10, maxPublicTtlMinutes: 30, maxPublicRedemptions: 10, blockedExtensions: [] };

export function AdminPoliciesPage() {
  const users = useQuery({ queryKey: ["admin-users"], queryFn: api.adminUsers });
  const [userId, setUserId] = useState("");
  useEffect(() => { if (!userId && users.data?.[0]) setUserId(users.data[0].id); }, [userId, users.data]);
  const current = useQuery({ queryKey: ["admin-policy", userId], queryFn: () => api.policy(userId), enabled: Boolean(userId) });
  const [policy, setPolicy] = useState<Policy>(defaultPolicy);
  useEffect(() => { if (current.data) setPolicy(current.data); }, [current.data]);
  const save = useMutation({ mutationFn: () => api.savePolicy(userId, policy), onSuccess: () => void current.refetch() });
  const toggle = (key: keyof Pick<Policy, "allowInternalSharing" | "allowPublicSharing" | "allowApiTokens" | "unlimited">) => setPolicy((value) => ({ ...value, [key]: !value[key] }));
  return (
    <AdminLayout title="User policies" description="Set quota and capability boundaries per person.">
      {users.isPending ? <LoadingState compact label="Loading users…" /> : users.isError ? <ErrorState error={users.error} /> : !users.data.length ? <EmptyState title="No users to configure" description="Create a member before assigning a policy." /> : <><div className="policy-picker"><Field label="Policy for"><select onChange={(event) => setUserId(event.target.value)} value={userId}>{users.data.map((user) => <option key={user.id} value={user.id}>{user.displayName || user.username} · @{user.username}</option>)}</select></Field></div>{current.isPending ? <LoadingState label="Loading policy…" /> : current.isError ? <ErrorState error={current.error} onRetry={() => void current.refetch()} /> : <div className="policy-grid"><section className="settings-section"><div className="settings-section__head"><h2>Capacity</h2><p>Quota includes active content, versions, and trash.</p></div><div className="settings-form"><div className="toggle-list"><div><div><strong>Unlimited storage</strong><p>Ignore the personal quota; host reserve still applies.</p></div><button aria-checked={policy.unlimited} className="switch" onClick={() => toggle("unlimited")} role="switch" type="button"><span /></button></div></div><div className="form-grid"><Field label="Quota"><div className="input-suffix"><input disabled={policy.unlimited} min={1} onChange={(event) => setPolicy({ ...policy, quotaBytes: Number(event.target.value) * 1024 ** 3 })} type="number" value={Math.round(policy.quotaBytes / 1024 ** 3)} /><span>GB</span></div></Field><Field label="Max item count"><input min={1} onChange={(event) => setPolicy({ ...policy, maxItems: Number(event.target.value) })} type="number" value={policy.maxItems} /></Field><Field label="Max single file"><div className="input-suffix"><input min={0} onChange={(event) => setPolicy({ ...policy, maxFileBytes: Number(event.target.value) * 1024 ** 2 || null })} placeholder="Unlimited" type="number" value={policy.maxFileBytes ? Math.round(policy.maxFileBytes / 1024 ** 2) : ""} /><span>MB</span></div></Field><Field label="Blocked extensions" hint="Comma-separated"><input onChange={(event) => setPolicy({ ...policy, blockedExtensions: event.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} placeholder="exe, dmg" value={policy.blockedExtensions.join(", ")} /></Field></div></div></section><section className="settings-section"><div className="settings-section__head"><h2>Capabilities</h2><p>Control outward access and upload pressure.</p></div><div className="toggle-list">{([['allowInternalSharing', 'Internal sharing', 'Share with existing members.'], ['allowPublicSharing', 'Public sharing', 'Create short-lived five-digit codes.'], ['allowApiTokens', 'Developer tokens', 'Use the external API.']] as const).map(([key, label, hint]) => <div key={key}><div><strong>{label}</strong><p>{hint}</p></div><button aria-checked={policy[key]} className="switch" onClick={() => toggle(key)} role="switch" type="button"><span /></button></div>)}</div><div className="form-grid"><Field label="Concurrent uploads"><input max={20} min={1} onChange={(event) => setPolicy({ ...policy, maxConcurrentUploads: Number(event.target.value) })} type="number" value={policy.maxConcurrentUploads} /></Field><Field label="Pending uploads"><input max={100} min={1} onChange={(event) => setPolicy({ ...policy, maxPendingUploads: Number(event.target.value) })} type="number" value={policy.maxPendingUploads} /></Field><Field label="Active public shares"><input max={1000} min={0} onChange={(event) => setPolicy({ ...policy, maxActivePublicShares: Number(event.target.value) })} type="number" value={policy.maxActivePublicShares} /></Field><Field label="Max public lifetime"><div className="input-suffix"><input max={30} min={1} onChange={(event) => setPolicy({ ...policy, maxPublicTtlMinutes: Number(event.target.value) })} type="number" value={policy.maxPublicTtlMinutes} /><span>min</span></div></Field></div></section></div>}{save.error ? <p className="form-error">{describeError(save.error)}</p> : null}<div className="settings-actions"><Button disabled={save.isPending || current.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save policy"}</Button></div></>}
    </AdminLayout>
  );
}

export function AdminAuditPage() {
  const events = useQuery({ queryKey: ["admin-audit"], queryFn: api.auditEvents });
  return (
    <AdminLayout title="Audit log" description="Security-sensitive actions and administrative accountability." action={<a className="button button--secondary" href="/api/v1/admin/audit?format=csv"><ArrowDownToLine size={16} />Export CSV</a>}>
      <div className="audit-callout"><ShieldCheck size={20} /><div><strong>Append-only at the application layer</strong><p>The host administrator can still alter local storage. Export logs to a separate system when tamper resistance is required.</p></div></div>
      {events.isPending ? <SkeletonRows /> : events.isError ? <ErrorState error={events.error} onRetry={() => void events.refetch()} /> : !events.data.length ? <EmptyState title="No audit events" description="Authentication, sharing, purge, and administrative events will appear here." /> : <div className="audit-list">{events.data.map((event) => <article className="audit-event" key={event.id}><span className="audit-event__icon"><Activity size={17} /></span><div><div><strong>{event.summary}</strong><StatusPill>{event.action.replaceAll("_", " ")}</StatusPill></div><p>{event.actor ? event.actor.displayName || event.actor.username : "System"}{event.targetType ? ` · ${event.targetType}` : ""}{event.ipAddress ? ` · ${event.ipAddress}` : ""}</p></div><time dateTime={event.createdAt}>{formatRelativeDate(event.createdAt)}</time></article>)}</div>}
    </AdminLayout>
  );
}

export function AdminSettingsPage() {
  const settings = useQuery({ queryKey: ["admin-settings"], queryFn: api.settings });
  const [form, setForm] = useState<InstanceSettings | null>(null);
  useEffect(() => { if (settings.data) setForm(settings.data); }, [settings.data]);
  const save = useMutation({ mutationFn: () => form ? api.saveSettings(form) : Promise.resolve(null), onSuccess: () => void settings.refetch() });
  return (
    <AdminLayout title="Instance settings" description="Public identity, filesystem safeguards, and trusted network boundaries.">
      {settings.isPending || !form ? <LoadingState label="Loading instance settings…" /> : settings.isError ? <ErrorState error={settings.error} onRetry={() => void settings.refetch()} /> : <><div className="settings-section"><div className="settings-section__head"><h2>Identity</h2><p>How this Arca appears to members and in generated links.</p></div><div className="settings-form"><div className="form-grid"><Field label="Instance name"><input onChange={(event) => setForm({ ...form, instanceName: event.target.value })} value={form.instanceName} /></Field><Field label="Public URL"><input onChange={(event) => setForm({ ...form, publicUrl: event.target.value })} type="url" value={form.publicUrl} /></Field></div><div className="toggle-list"><div><div><strong>Allow account requests</strong><p>Show the public request-access flow.</p></div><button aria-checked={form.allowAccessRequests} className="switch" onClick={() => setForm({ ...form, allowAccessRequests: !form.allowAccessRequests })} role="switch" type="button"><span /></button></div></div></div></div><div className="settings-section"><div className="settings-section__head"><h2>Storage safety</h2><p>Reserve physical headroom before uploads are accepted.</p></div><div className="settings-form"><Field label="Filesystem reserve"><div className="input-suffix"><input min={0} onChange={(event) => setForm({ ...form, filesystemReserveBytes: Number(event.target.value) * 1024 ** 3 })} type="number" value={form.filesystemReserveBytes / 1024 ** 3} /><span>GB</span></div></Field></div></div><div className="settings-section"><div className="settings-section__head"><h2>Trusted proxies</h2><p>Forwarded client IP headers are used only from these CIDR ranges.</p></div><div className="settings-form"><Field label="Proxy CIDRs" hint="One CIDR per line"><textarea onChange={(event) => setForm({ ...form, trustedProxyCidrs: event.target.value.split("\n").map((item) => item.trim()).filter(Boolean) })} placeholder="10.0.0.0/8" rows={4} value={form.trustedProxyCidrs.join("\n")} /></Field><div className="notice notice--warning"><AlertTriangle size={18} /><p>Incorrect proxy trust can undermine public-code rate limits. Configure only networks you control.</p></div></div></div><div className="settings-section"><div className="settings-section__head"><h2>Browser API access</h2><p>Allow browser applications only from explicitly trusted origins.</p></div><div className="settings-form"><Field label="Allowed CORS origins" hint="One exact origin per line; leave empty to deny cross-origin browser requests"><textarea onChange={(event) => setForm({ ...form, allowedCorsOrigins: event.target.value.split("\n").map((item) => item.trim()).filter(Boolean) })} placeholder="https://app.example.com" rows={4} value={form.allowedCorsOrigins.join("\n")} /></Field><div className="notice"><ShieldCheck size={18} /><p>Use complete origins such as https://app.example.com. Arca does not enable browser API access by default.</p></div></div></div>{save.error ? <p className="form-error">{describeError(save.error)}</p> : null}<div className="settings-actions"><Button disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save instance settings"}</Button></div></>}
    </AdminLayout>
  );
}
