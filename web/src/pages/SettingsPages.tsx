import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useRouterState } from "@tanstack/react-router";
import { Check, Code2, Copy, KeyRound, Laptop, Monitor, Moon, Palette, Plus, ShieldCheck, Smartphone, Sun, Trash2, UserRound } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { api, describeError } from "../api/client";
import type { Accent, ThemeMode, User } from "../api/types";
import { useAppearance } from "../app/appearance";
import { formatRelativeDate } from "../lib";
import { Button, EmptyState, ErrorState, Field, IconButton, LoadingState, Modal, StatusPill } from "../components/Primitives";

const settingsLinks = [
  { to: "/settings/profile", label: "Profile", icon: UserRound },
  { to: "/settings/appearance", label: "Appearance", icon: Palette },
  { to: "/settings/sessions", label: "Sessions", icon: Laptop },
  { to: "/settings/developer", label: "Developer", icon: Code2 },
];

function SettingsLayout({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  return (
    <div className="settings-layout">
      <aside className="settings-nav"><span className="eyebrow">Settings</span><nav>{settingsLinks.map((item) => { const Icon = item.icon; return <Link className={pathname === item.to ? "active" : ""} key={item.to} to={item.to}><Icon size={17} />{item.label}</Link>; })}</nav></aside>
      <section className="settings-content"><div className="page-heading"><h1>{title}</h1><p>{description}</p></div>{children}</section>
    </div>
  );
}

export function ProfileSettingsPage({ user }: { user: User }) {
  const queryClient = useQueryClient();
  const [displayName, setDisplayName] = useState(user.displayName ?? "");
  const update = useMutation({
    mutationFn: () => api.updateProfile({ displayName: displayName.trim() }),
    onSuccess: (nextUser) => queryClient.setQueryData(["session"], (current: unknown) => {
      if (!current || typeof current !== "object") return current;
      return { ...current, user: nextUser };
    }),
  });
  return (
    <SettingsLayout title="Profile" description="How your name and account appear to people in this Arca.">
      <div className="settings-section"><div className="settings-section__head"><h2>Personal details</h2><p>Your username and email are managed by your administrator.</p></div><div className="settings-form"><Field label="Display name"><input autoComplete="name" onChange={(event) => setDisplayName(event.target.value)} value={displayName} /></Field><div className="form-grid"><Field label="Username"><input disabled value={user.username} /></Field><Field label="Email address"><input disabled value={user.email} /></Field></div>{update.error ? <p className="form-error">{describeError(update.error)}</p> : update.isSuccess ? <p className="form-success"><Check size={15} />Profile saved</p> : null}<div><Button disabled={update.isPending || displayName.trim() === (user.displayName ?? "")} onClick={() => update.mutate()}>{update.isPending ? "Saving…" : "Save profile"}</Button></div></div></div>
      <div className="settings-section"><div className="settings-section__head"><h2>Account</h2><p>Your current role and storage state.</p></div><dl className="inline-details"><div><dt>Role</dt><dd><StatusPill tone={user.role === "superadmin" ? "accent" : "neutral"}>{user.role === "superadmin" ? "Superadmin" : "Member"}</StatusPill></dd></div><div><dt>Status</dt><dd><StatusPill tone={user.state === "active" ? "success" : "warning"}>{user.state.replace("_", " ")}</StatusPill></dd></div><div><dt>Member since</dt><dd>{formatRelativeDate(user.createdAt)}</dd></div></dl></div>
    </SettingsLayout>
  );
}

const accents: Array<{ value: Accent; label: string }> = [
  { value: "violet", label: "Violet" }, { value: "indigo", label: "Indigo" }, { value: "blue", label: "Blue" }, { value: "cyan", label: "Cyan" },
  { value: "teal", label: "Teal" }, { value: "green", label: "Green" }, { value: "amber", label: "Amber" }, { value: "rose", label: "Rose" },
];

export function AppearanceSettingsPage({ user }: { user: User }) {
  const { preferences, setPreferences } = useAppearance();
  const queryClient = useQueryClient();
  useEffect(() => setPreferences(user.preferences), [setPreferences, user.preferences]);
  const save = useMutation({ mutationFn: () => api.updatePreferences(preferences), onSuccess: (saved) => { setPreferences(saved); void queryClient.invalidateQueries({ queryKey: ["session"] }); } });
  const modes: Array<{ value: ThemeMode; label: string; icon: typeof Monitor }> = [{ value: "system", label: "System", icon: Monitor }, { value: "light", label: "Light", icon: Sun }, { value: "dark", label: "Dark", icon: Moon }];
  return (
    <SettingsLayout title="Appearance" description="Shape the vault around the way you work. Preferences follow your account.">
      <div className="settings-section"><div className="settings-section__head"><h2>Color mode</h2><p>Use your device setting or choose a permanent mode.</p></div><div className="theme-options">{modes.map((mode) => { const Icon = mode.icon; return <button aria-pressed={preferences.themeMode === mode.value} className={preferences.themeMode === mode.value ? "active" : ""} key={mode.value} onClick={() => setPreferences({ ...preferences, themeMode: mode.value })} type="button"><span className={`theme-preview theme-preview--${mode.value}`}><i /><b /><em /></span><span><Icon size={17} />{mode.label}{preferences.themeMode === mode.value ? <Check size={15} /> : null}</span></button>; })}</div></div>
      <div className="settings-section"><div className="settings-section__head"><h2>Accent</h2><p>A restrained highlight used for focus and primary actions.</p></div><div className="accent-options">{accents.map((accent) => <button aria-label={accent.label} aria-pressed={preferences.accent === accent.value} className={preferences.accent === accent.value ? "active" : ""} data-color={accent.value} key={accent.value} onClick={() => setPreferences({ ...preferences, accent: accent.value })} title={accent.label} type="button"><span />{preferences.accent === accent.value ? <Check size={14} /> : null}</button>)}</div></div>
      <div className="settings-section"><div className="settings-section__head"><h2>Comfort</h2><p>Control information density and nonessential movement.</p></div><div className="toggle-list"><div><div><strong>Compact file lists</strong><p>Show more items without reducing legibility.</p></div><button aria-checked={preferences.density === "compact"} className="switch" onClick={() => setPreferences({ ...preferences, density: preferences.density === "compact" ? "comfortable" : "compact" })} role="switch" type="button"><span /></button></div><div><div><strong>Reduce motion</strong><p>Remove decorative transitions and movement.</p></div><button aria-checked={preferences.reducedMotion} className="switch" onClick={() => setPreferences({ ...preferences, reducedMotion: !preferences.reducedMotion })} role="switch" type="button"><span /></button></div></div></div>
      {save.error ? <p className="form-error">{describeError(save.error)}</p> : null}<div className="settings-actions"><Button disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save appearance"}</Button></div>
    </SettingsLayout>
  );
}

function deviceIcon(agent: string) {
  return /mobile|android|iphone/i.test(agent) ? Smartphone : Laptop;
}

export function SessionsSettingsPage() {
  const queryClient = useQueryClient();
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: api.sessions });
  const revoke = useMutation({ mutationFn: api.revokeSession, onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["sessions"] }) });
  return (
    <SettingsLayout title="Sessions" description="Review devices signed in to your account and revoke anything unfamiliar.">
      <div className="settings-section"><div className="settings-section__head"><h2>Active sessions</h2><p>Sessions are managed through WorkOS and checked against your local account on every request.</p></div>{sessions.isPending ? <LoadingState compact label="Loading sessions…" /> : sessions.isError ? <ErrorState error={sessions.error} onRetry={() => void sessions.refetch()} /> : !sessions.data.length ? <EmptyState title="No sessions reported" description="Your current authentication provider did not return session details." /> : <div className="device-list">{sessions.data.map((session) => { const Icon = deviceIcon(session.userAgent); return <div className="device" key={session.id}><span className="device__icon"><Icon size={19} /></span><div><strong>{session.userAgent}</strong><span>{session.ipAddress ?? "IP unavailable"} · Active {formatRelativeDate(session.lastActiveAt)}</span></div>{session.current ? <StatusPill tone="success">This device</StatusPill> : <Button disabled={revoke.isPending} onClick={() => revoke.mutate(session.id)} variant="secondary">Revoke</Button>}</div>; })}</div>}</div>
    </SettingsLayout>
  );
}

const scopes = [
  { value: "files:read", label: "Read files" }, { value: "files:write", label: "Write files" }, { value: "shares:read", label: "Read shares" }, { value: "shares:write", label: "Manage shares" }, { value: "tokens:manage", label: "Manage tokens" },
];

export function DeveloperSettingsPage({ user }: { user: User }) {
  const queryClient = useQueryClient();
  const tokens = useQuery({ queryKey: ["tokens"], queryFn: api.tokens });
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<string[]>(["files:read"]);
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const create = useMutation({ mutationFn: () => api.createToken({ name: name.trim(), scopes: selectedScopes, expiresAt: null }), onSuccess: (token) => { setPlaintext(token.token ?? null); void queryClient.invalidateQueries({ queryKey: ["tokens"] }); } });
  const revoke = useMutation({ mutationFn: api.revokeToken, onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["tokens"] }) });
  return (
    <SettingsLayout title="Developer" description="Build against Arca’s versioned API with scoped personal access tokens.">
      <div className="api-callout"><span><Code2 size={21} /></span><div><strong>REST API v1</strong><p>Typed resources, cursor pagination, ETags, and RFC 9457 errors.</p></div><a className="button button--secondary" href="/api/docs" rel="noreferrer" target="_blank">Open API docs</a></div>
      <div className="settings-section"><div className="settings-section__head settings-section__head--action"><div><h2>Personal access tokens</h2><p>Tokens are shown once. Keep them somewhere secure.</p></div><Button onClick={() => { setCreateOpen(true); setPlaintext(null); }}><Plus size={16} />Create token</Button></div>{tokens.isPending ? <LoadingState compact label="Loading tokens…" /> : tokens.isError ? <ErrorState error={tokens.error} onRetry={() => void tokens.refetch()} /> : !tokens.data.length ? <EmptyState title="No API tokens" description="Create a narrowly scoped token when an integration needs access." /> : <div className="token-list">{tokens.data.map((token) => <div className="token-row" key={token.id}><span className="token-row__icon"><KeyRound size={18} /></span><div><strong>{token.name}</strong><code>{token.prefix}</code><span>{token.scopes.join(" · ")} · Created {formatRelativeDate(token.createdAt)}</span></div><IconButton label={`Revoke ${token.name}`} onClick={() => revoke.mutate(token.id)}><Trash2 size={17} /></IconButton></div>)}</div>}</div>
      <Modal open={createOpen} onOpenChange={(open) => { setCreateOpen(open); if (!open) { setPlaintext(null); create.reset(); } }} title={plaintext ? "Token created" : "Create a personal token"} description={plaintext ? "Copy it now. Arca stores only a cryptographic hash and cannot reveal it again." : "Give this integration only the permissions it actually needs."}>
        {plaintext ? <div className="token-result"><code>{plaintext}</code><Button onClick={() => void navigator.clipboard.writeText(plaintext)}><Copy size={16} />Copy token</Button><div className="notice notice--warning"><ShieldCheck size={18} /><p>Treat this value like a password. Close this dialog only after saving it.</p></div></div> : <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); create.mutate(); }}><Field label="Token name"><input autoFocus onChange={(event) => setName(event.target.value)} placeholder="Reporting integration" required value={name} /></Field><fieldset className="scope-field"><legend>Scopes</legend>{scopes.map((scope) => <label key={scope.value}><input checked={selectedScopes.includes(scope.value)} onChange={(event) => setSelectedScopes((current) => event.target.checked ? [...current, scope.value] : current.filter((item) => item !== scope.value))} type="checkbox" /><span><Check size={12} /></span>{scope.label}</label>)}{user.role === "superadmin" ? <label><input checked={selectedScopes.includes("admin:*")} onChange={(event) => setSelectedScopes((current) => event.target.checked ? [...current, "admin:*"] : current.filter((item) => item !== "admin:*"))} type="checkbox" /><span><Check size={12} /></span>Administrator access</label> : null}</fieldset>{create.error ? <p className="form-error">{describeError(create.error)}</p> : null}<div className="dialog-actions"><Button variant="ghost" onClick={() => setCreateOpen(false)} type="button">Cancel</Button><Button disabled={!name.trim() || selectedScopes.length === 0 || create.isPending}>{create.isPending ? "Creating…" : "Create token"}</Button></div></form>}
      </Modal>
    </SettingsLayout>
  );
}
