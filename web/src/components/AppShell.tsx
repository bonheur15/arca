import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Archive,
  Clock3,
  Cloud,
  Code2,
  FileStack,
  Folder,
  Gauge,
  HardDrive,
  KeyRound,
  LogOut,
  Menu,
  Palette,
  Plus,
  Search,
  Settings,
  Share2,
  ShieldCheck,
  Sparkles,
  Star,
  Trash2,
  Upload,
  UserRoundCog,
  Users,
  X,
} from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { User } from "../api/types";
import { formatBytes, initials } from "../lib";
import { useUploads, UploadTray } from "../features/uploads/UploadManager";
import { ArcaMark } from "./ArcaMark";
import { Button, IconButton, Modal } from "./Primitives";

interface NavItem {
  label: string;
  to: string;
  icon: typeof Folder;
}

const personalNav: NavItem[] = [
  { label: "My files", to: "/files", icon: Folder },
  { label: "Shared", to: "/shared", icon: Share2 },
  { label: "Recent", to: "/recent", icon: Clock3 },
  { label: "Starred", to: "/starred", icon: Star },
  { label: "Trash", to: "/trash", icon: Trash2 },
];

const adminNav: NavItem[] = [
  { label: "Users", to: "/admin/users", icon: Users },
  { label: "Requests", to: "/admin/requests", icon: UserRoundCog },
  { label: "Storage", to: "/admin/storage", icon: HardDrive },
  { label: "Policies", to: "/admin/policies", icon: ShieldCheck },
  { label: "Audit", to: "/admin/audit", icon: FileStack },
  { label: "Instance", to: "/admin/settings", icon: Gauge },
];

function NavLink({ item, onNavigate }: { item: NavItem; onNavigate?: () => void }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const active = pathname === item.to || (item.to === "/files" && pathname.startsWith("/files/"));
  const Icon = item.icon;
  return (
    <Link aria-current={active ? "page" : undefined} className={`nav-link ${active ? "nav-link--active" : ""}`} onClick={onNavigate} to={item.to}>
      <Icon size={18} strokeWidth={active ? 2.2 : 1.8} />
      <span>{item.label}</span>
    </Link>
  );
}

function UserMenu({ user }: { user: User }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: async () => {
      queryClient.clear();
      await navigate({ to: "/sign-in" });
    },
  });
  const displayName = user.displayName || user.username;
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button className="user-trigger" type="button">
          <span className="avatar">{initials(displayName)}</span>
          <span className="user-trigger__copy"><strong>{displayName}</strong><small>@{user.username}</small></span>
          <Menu size={16} />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" className="dropdown" sideOffset={8}>
          <div className="dropdown__identity"><strong>{displayName}</strong><span>{user.email}</span></div>
          <DropdownMenu.Separator className="dropdown__separator" />
          <DropdownMenu.Item asChild><Link className="dropdown__item" to="/settings/profile"><Settings size={16} />Account settings</Link></DropdownMenu.Item>
          <DropdownMenu.Item asChild><Link className="dropdown__item" to="/settings/appearance"><Palette size={16} />Appearance</Link></DropdownMenu.Item>
          <DropdownMenu.Item asChild><Link className="dropdown__item" to="/settings/developer"><Code2 size={16} />Developer</Link></DropdownMenu.Item>
          <DropdownMenu.Separator className="dropdown__separator" />
          <DropdownMenu.Item className="dropdown__item dropdown__item--danger" disabled={logout.isPending} onSelect={() => logout.mutate()}>
            <LogOut size={16} />Sign out
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function CommandPalette({ open, onOpenChange, user }: { open: boolean; onOpenChange: (open: boolean) => void; user: User }) {
  const navigate = useNavigate();
  const commands = useMemo(() => [
    ...personalNav,
    { label: "Appearance", to: "/settings/appearance", icon: Palette },
    { label: "Developer tokens", to: "/settings/developer", icon: KeyRound },
    ...(user.role === "superadmin" ? adminNav : []),
  ], [user.role]);
  const [query, setQuery] = useState("");
  const matches = commands.filter((command) => command.label.toLowerCase().includes(query.toLowerCase()));
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Go somewhere" description="Find a place in Arca or use a keyboard shortcut.">
      <div className="command-search"><Search size={18} /><input autoFocus placeholder="Search commands…" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
      <div className="command-list">
        {matches.map((command) => {
          const Icon = command.icon;
          return <button key={command.to} onClick={() => { void navigate({ to: command.to }); onOpenChange(false); }} type="button"><Icon size={18} /><span>{command.label}</span></button>;
        })}
      </div>
      <div className="command-hints"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span></div>
    </Modal>
  );
}

export function AppShell({ user, children }: { user: User; children: ReactNode }) {
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const [mobileNav, setMobileNav] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [search, setSearch] = useState("");
  const uploadInput = useRef<HTMLInputElement>(null);
  const { addFiles } = useUploads();
  const quota = user.quota;
  const usedPercent = quota.unlimited || quota.quotaBytes === 0 ? 0 : Math.min(100, (quota.usedBytes / quota.quotaBytes) * 100);
  const folderId = pathname.startsWith("/files/") ? pathname.slice("/files/".length).split("/")[0] ?? null : null;

  useEffect(() => {
    const handleKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const editing = target?.matches("input, textarea, select, [contenteditable='true']");
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen(true);
      } else if (!editing && event.key === "/") {
        event.preventDefault();
        document.querySelector<HTMLInputElement>("#global-search")?.focus();
      } else if (!editing && event.key.toLowerCase() === "u") {
        event.preventDefault();
        uploadInput.current?.click();
      } else if (!editing && event.key.toLowerCase() === "n") {
        event.preventDefault();
        window.dispatchEvent(new CustomEvent("arca:new-folder"));
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const handleSearch = (event: React.FormEvent) => {
    event.preventDefault();
    const query = search.trim();
    if (query) void navigate({ to: "/search", search: { q: query } });
  };

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <AnimatePresence>
        {mobileNav ? <motion.button aria-label="Close navigation" className="nav-scrim" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setMobileNav(false)} /> : null}
      </AnimatePresence>
      <aside className={`sidebar ${mobileNav ? "sidebar--open" : ""}`}>
        <div className="sidebar__brand">
          <Link aria-label="Arca home" className="brand" to="/files"><ArcaMark size={31} /><span>arca</span></Link>
          <IconButton className="sidebar__close" label="Close navigation" onClick={() => setMobileNav(false)}><X size={18} /></IconButton>
        </div>
        <div className="sidebar__new">
          <Button className="new-button" onClick={() => uploadInput.current?.click()}><Plus size={18} /><span>New upload</span></Button>
          <input
            className="sr-only"
            multiple
            onChange={(event) => {
              const files = Array.from(event.target.files ?? []);
              if (files.length) addFiles(files, folderId);
              event.target.value = "";
            }}
            ref={uploadInput}
            type="file"
          />
        </div>
        <nav aria-label="File navigation" className="sidebar__nav">
          <span className="nav-label">Workspace</span>
          {personalNav.map((item) => <NavLink item={item} key={item.to} onNavigate={() => setMobileNav(false)} />)}
          {user.role === "superadmin" ? (
            <>
              <span className="nav-label nav-label--section">Administration</span>
              {adminNav.map((item) => <NavLink item={item} key={item.to} onNavigate={() => setMobileNav(false)} />)}
            </>
          ) : null}
        </nav>
        <div className="sidebar__bottom">
          <div className="quota-card">
            <div className="quota-card__line"><span>Storage</span><strong>{quota.unlimited ? formatBytes(quota.usedBytes) : `${Math.round(usedPercent)}%`}</strong></div>
            <div aria-label={`${Math.round(usedPercent)} percent storage used`} aria-valuemax={100} aria-valuemin={0} aria-valuenow={usedPercent} className="quota-bar" role="progressbar"><span style={{ width: `${usedPercent}%` }} /></div>
            <p>{quota.unlimited ? "Unlimited plan" : `${formatBytes(quota.usedBytes)} of ${formatBytes(quota.quotaBytes)}`}</p>
          </div>
          <UserMenu user={user} />
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <IconButton className="mobile-menu" label="Open navigation" onClick={() => setMobileNav(true)}><Menu size={20} /></IconButton>
          <form className="global-search" onSubmit={handleSearch} role="search">
            <Search aria-hidden="true" size={18} />
            <input aria-label="Search files" id="global-search" onChange={(event) => setSearch(event.target.value)} placeholder="Search the vault" value={search} />
            <kbd>/</kbd>
          </form>
          <button className="command-trigger" onClick={() => setCommandOpen(true)} type="button"><Sparkles size={16} /><span>Commands</span><kbd>⌘K</kbd></button>
          <span className="topbar-avatar"><span className="avatar avatar--small">{initials(user.displayName || user.username)}</span></span>
        </header>
        {user.state === "over_quota" ? <div className="system-banner"><Cloud size={17} /><span>Your storage is over quota. Downloads and cleanup remain available, but new uploads are paused.</span></div> : null}
        <main className="main" id="main-content">{children}</main>
      </div>
      <nav aria-label="Mobile navigation" className="bottom-nav">
        {personalNav.slice(0, 4).map((item) => {
          const Icon = item.icon;
          const active = pathname === item.to || (item.to === "/files" && pathname.startsWith("/files/"));
          return <Link aria-current={active ? "page" : undefined} className={active ? "active" : ""} key={item.to} to={item.to}><Icon size={20} /><span>{item.label.replace("My ", "")}</span></Link>;
        })}
        <button onClick={() => uploadInput.current?.click()} type="button"><span className="bottom-new"><Upload size={20} /></span><span>Upload</span></button>
      </nav>
      <CommandPalette open={commandOpen} onOpenChange={setCommandOpen} user={user} />
      <UploadTray />
    </div>
  );
}
