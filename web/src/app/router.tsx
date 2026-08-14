import { QueryClient } from "@tanstack/react-query";
import { createRootRoute, createRoute, createRouter, Link, Navigate, Outlet } from "@tanstack/react-router";
import { lazy, Suspense, useEffect, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { ApiError, api } from "../api/client";
import { AppShell } from "../components/AppShell";
import { ArcaMark } from "../components/ArcaMark";
import { Button, ErrorState, LoadingState } from "../components/Primitives";
import { UploadProvider } from "../features/uploads/UploadManager";
import { normalizeSupportUser } from "../features/files/supportMode";
import { useAppearance } from "./appearance";

const FileBrowser = lazy(() => import("../features/files/FileViews").then((module) => ({ default: module.FileBrowser })));
const SetupPage = lazy(() => import("../pages/AuthPages").then((module) => ({ default: module.SetupPage })));
const SignInPage = lazy(() => import("../pages/AuthPages").then((module) => ({ default: module.SignInPage })));
const RequestAccessPage = lazy(() => import("../pages/AuthPages").then((module) => ({ default: module.RequestAccessPage })));
const RedeemPage = lazy(() => import("../pages/AuthPages").then((module) => ({ default: module.RedeemPage })));
const PublicPage = lazy(() => import("../pages/AuthPages").then((module) => ({ default: module.PublicPage })));
const ProfileSettingsPage = lazy(() => import("../pages/SettingsPages").then((module) => ({ default: module.ProfileSettingsPage })));
const AppearanceSettingsPage = lazy(() => import("../pages/SettingsPages").then((module) => ({ default: module.AppearanceSettingsPage })));
const SessionsSettingsPage = lazy(() => import("../pages/SettingsPages").then((module) => ({ default: module.SessionsSettingsPage })));
const DeveloperSettingsPage = lazy(() => import("../pages/SettingsPages").then((module) => ({ default: module.DeveloperSettingsPage })));
const AdminUsersPage = lazy(() => import("../pages/AdminPages").then((module) => ({ default: module.AdminUsersPage })));
const AdminRequestsPage = lazy(() => import("../pages/AdminPages").then((module) => ({ default: module.AdminRequestsPage })));
const AdminStoragePage = lazy(() => import("../pages/AdminPages").then((module) => ({ default: module.AdminStoragePage })));
const AdminPoliciesPage = lazy(() => import("../pages/AdminPages").then((module) => ({ default: module.AdminPoliciesPage })));
const AdminAuditPage = lazy(() => import("../pages/AdminPages").then((module) => ({ default: module.AdminAuditPage })));
const AdminSettingsPage = lazy(() => import("../pages/AdminPages").then((module) => ({ default: module.AdminSettingsPage })));

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 20_000,
      retry: (failureCount, error) => !(error instanceof ApiError && error.status >= 400 && error.status < 500) && failureCount < 2,
      refetchOnWindowFocus: true,
    },
    mutations: { retry: false },
  },
});

function RootComponent() {
  return <Suspense fallback={<div className="boot-screen"><ArcaMark size={42} /><LoadingState label="Opening Arca…" compact /></div>}><Outlet /></Suspense>;
}

function ProtectedPage({ children, admin = false }: { children: (user: NonNullable<Awaited<ReturnType<typeof api.session>>["user"]>) => ReactNode; admin?: boolean }) {
  const { setPreferences } = useAppearance();
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrapStatus, retry: false });
  const session = useQuery({ queryKey: ["session"], queryFn: api.session, retry: false, enabled: bootstrap.data?.initialized === true });
  useEffect(() => {
    if (session.data?.csrfToken) {
      let meta = document.querySelector<HTMLMetaElement>('meta[name="arca-csrf"]');
      if (!meta) { meta = document.createElement("meta"); meta.name = "arca-csrf"; document.head.append(meta); }
      meta.content = session.data.csrfToken;
    }
    if (session.data?.user) setPreferences(session.data.user.preferences);
  }, [session.data, setPreferences]);
  if (bootstrap.isPending) return <div className="boot-screen"><ArcaMark size={42} /><LoadingState label="Opening Arca…" compact /></div>;
  if (bootstrap.isError) return <div className="boot-screen"><ErrorState error={bootstrap.error} onRetry={() => void bootstrap.refetch()} title="Arca is not ready" /></div>;
  if (!bootstrap.data.initialized) return <Navigate to="/setup" replace />;
  if (session.isPending) return <div className="boot-screen"><ArcaMark size={42} /><LoadingState label="Unlocking your workspace…" compact /></div>;
  if (session.isError && session.error instanceof ApiError && session.error.status === 401) return <Navigate to="/sign-in" replace />;
  if (session.isError) return <div className="boot-screen"><ErrorState error={session.error} onRetry={() => void session.refetch()} title="Your session could not be checked" /></div>;
  if (!session.data.authenticated || !session.data.user) return <Navigate to="/sign-in" replace />;
  if (admin && session.data.user.role !== "superadmin") return <Navigate to="/files" replace />;
  return <UploadProvider><AppShell user={session.data.user}>{children(session.data.user)}</AppShell></UploadProvider>;
}

function NotFoundPage() {
  return <div className="not-found"><ArcaMark size={46} /><span>404</span><h1>This path ends here.</h1><p>The item may have moved, expired, or never existed.</p><Button onClick={() => history.back()} variant="secondary">Go back</Button><Link to="/files">Return to my files</Link></div>;
}

const rootRoute = createRootRoute({ component: RootComponent, notFoundComponent: NotFoundPage });

const setupRoute = createRoute({ getParentRoute: () => rootRoute, path: "/setup", component: SetupPage });
const signInRoute = createRoute({ getParentRoute: () => rootRoute, path: "/sign-in", component: SignInPage });
const requestAccessRoute = createRoute({ getParentRoute: () => rootRoute, path: "/request-access", component: RequestAccessPage });
const redeemRoute = createRoute({ getParentRoute: () => rootRoute, path: "/redeem", component: RedeemPage });
const publicRoute = createRoute({ getParentRoute: () => rootRoute, path: "/public", component: PublicPage });

interface FileSearch {
  view?: "grid" | "list";
  sort?: string;
  order?: "asc" | "desc";
  support_user?: string;
}

function validateFileSearch(search: Record<string, unknown>): FileSearch {
  const supportUserId = normalizeSupportUser(search.support_user);
  return {
    ...(search.view === "grid" || search.view === "list" ? { view: search.view } : {}),
    ...(typeof search.sort === "string" ? { sort: search.sort } : {}),
    ...(search.order === "desc" || search.order === "asc" ? { order: search.order } : {}),
    ...(supportUserId ? { support_user: supportUserId } : {}),
  };
}

function validateGlobalSearch(search: Record<string, unknown>): FileSearch & { q?: string } {
  return {
    ...validateFileSearch(search),
    ...(typeof search.q === "string" ? { q: search.q } : {}),
  };
}

const filesRoute = createRoute({ getParentRoute: () => rootRoute, path: "/files", validateSearch: validateFileSearch, component: () => { const { support_user: supportUserId } = filesRoute.useSearch(); return <ProtectedPage>{(user) => <FileBrowser collection="files" currentUserId={user.id} supportUserId={supportUserId} />}</ProtectedPage>; } });
const folderRoute = createRoute({ getParentRoute: () => rootRoute, path: "/files/$folderId", validateSearch: validateFileSearch, component: () => { const { folderId } = folderRoute.useParams(); const { support_user: supportUserId } = folderRoute.useSearch(); return <ProtectedPage>{(user) => <FileBrowser collection="files" currentUserId={user.id} folderId={folderId} supportUserId={supportUserId} />}</ProtectedPage>; } });
const recentRoute = createRoute({ getParentRoute: () => rootRoute, path: "/recent", validateSearch: validateFileSearch, component: () => <ProtectedPage>{(user) => <FileBrowser collection="recent" currentUserId={user.id} />}</ProtectedPage> });
const starredRoute = createRoute({ getParentRoute: () => rootRoute, path: "/starred", validateSearch: validateFileSearch, component: () => <ProtectedPage>{(user) => <FileBrowser collection="favorites" currentUserId={user.id} />}</ProtectedPage> });
const sharedRoute = createRoute({ getParentRoute: () => rootRoute, path: "/shared", validateSearch: validateFileSearch, component: () => <ProtectedPage>{(user) => <FileBrowser collection="shared" currentUserId={user.id} />}</ProtectedPage> });
const trashRoute = createRoute({ getParentRoute: () => rootRoute, path: "/trash", validateSearch: validateFileSearch, component: () => <ProtectedPage>{(user) => <FileBrowser collection="trash" currentUserId={user.id} />}</ProtectedPage> });
const searchRoute = createRoute({ getParentRoute: () => rootRoute, path: "/search", validateSearch: validateGlobalSearch, component: () => { const { q } = searchRoute.useSearch(); return <ProtectedPage>{(user) => <FileBrowser collection="search" currentUserId={user.id} query={q ?? ""} />}</ProtectedPage>; } });

const profileRoute = createRoute({ getParentRoute: () => rootRoute, path: "/settings/profile", component: () => <ProtectedPage>{(user) => <ProfileSettingsPage user={user} />}</ProtectedPage> });
const appearanceRoute = createRoute({ getParentRoute: () => rootRoute, path: "/settings/appearance", component: () => <ProtectedPage>{(user) => <AppearanceSettingsPage user={user} />}</ProtectedPage> });
const sessionsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/settings/sessions", component: () => <ProtectedPage>{() => <SessionsSettingsPage />}</ProtectedPage> });
const developerRoute = createRoute({ getParentRoute: () => rootRoute, path: "/settings/developer", component: () => <ProtectedPage>{(user) => <DeveloperSettingsPage user={user} />}</ProtectedPage> });

const adminUsersRoute = createRoute({ getParentRoute: () => rootRoute, path: "/admin/users", component: () => <ProtectedPage admin>{() => <AdminUsersPage />}</ProtectedPage> });
const adminRequestsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/admin/requests", component: () => <ProtectedPage admin>{() => <AdminRequestsPage />}</ProtectedPage> });
const adminStorageRoute = createRoute({ getParentRoute: () => rootRoute, path: "/admin/storage", component: () => <ProtectedPage admin>{() => <AdminStoragePage />}</ProtectedPage> });
const adminPoliciesRoute = createRoute({ getParentRoute: () => rootRoute, path: "/admin/policies", component: () => <ProtectedPage admin>{() => <AdminPoliciesPage />}</ProtectedPage> });
const adminAuditRoute = createRoute({ getParentRoute: () => rootRoute, path: "/admin/audit", component: () => <ProtectedPage admin>{() => <AdminAuditPage />}</ProtectedPage> });
const adminSettingsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/admin/settings", component: () => <ProtectedPage admin>{() => <AdminSettingsPage />}</ProtectedPage> });

const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: () => <Navigate to="/files" replace /> });

const routeTree = rootRoute.addChildren([
  indexRoute,
  setupRoute,
  signInRoute,
  requestAccessRoute,
  redeemRoute,
  publicRoute,
  filesRoute,
  folderRoute,
  recentRoute,
  starredRoute,
  sharedRoute,
  trashRoute,
  searchRoute,
  profileRoute,
  appearanceRoute,
  sessionsRoute,
  developerRoute,
  adminUsersRoute,
  adminRequestsRoute,
  adminStorageRoute,
  adminPoliciesRoute,
  adminAuditRoute,
  adminSettingsRoute,
]);

export const router = createRouter({ routeTree, defaultPreload: "intent", defaultPreloadStaleTime: 0 });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
