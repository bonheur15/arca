import { QueryClient } from "@tanstack/react-query";
import { createRootRoute, createRoute, createRouter, Link, Navigate, Outlet } from "@tanstack/react-router";
import { createContext, lazy, Suspense, useContext, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { ApiError, api } from "../api/client";
import type { User } from "../api/types";
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

const ProtectedUserContext = createContext<User | null>(null);

function useProtectedUser(): User {
  const user = useContext(ProtectedUserContext);
  if (!user) throw new Error("useProtectedUser must be used inside ProtectedLayout");
  return user;
}

function ProtectedLayout() {
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
  return (
    <ProtectedUserContext.Provider value={session.data.user}>
      <UploadProvider>
        <AppShell user={session.data.user}>
          <Suspense fallback={<div className="route-loading"><LoadingState label="Opening page…" compact /></div>}>
            <Outlet />
          </Suspense>
        </AppShell>
      </UploadProvider>
    </ProtectedUserContext.Provider>
  );
}

function AdminLayout() {
  const user = useProtectedUser();
  return user.role === "superadmin" ? <Outlet /> : <Navigate to="/files" replace />;
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

const protectedRoute = createRoute({ getParentRoute: () => rootRoute, id: "authenticated", component: ProtectedLayout });
const adminRoute = createRoute({ getParentRoute: () => protectedRoute, id: "admin", component: AdminLayout });

const filesRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/files", validateSearch: validateFileSearch, component: () => { const user = useProtectedUser(); const { support_user: supportUserId } = filesRoute.useSearch(); return <FileBrowser collection="files" currentUserId={user.id} supportUserId={supportUserId} />; } });
const folderRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/files/$folderId", validateSearch: validateFileSearch, component: () => { const user = useProtectedUser(); const { folderId } = folderRoute.useParams(); const { support_user: supportUserId } = folderRoute.useSearch(); return <FileBrowser collection="files" currentUserId={user.id} folderId={folderId} supportUserId={supportUserId} />; } });
const recentRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/recent", validateSearch: validateFileSearch, component: () => { const user = useProtectedUser(); return <FileBrowser collection="recent" currentUserId={user.id} />; } });
const starredRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/starred", validateSearch: validateFileSearch, component: () => { const user = useProtectedUser(); return <FileBrowser collection="favorites" currentUserId={user.id} />; } });
const sharedRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/shared", validateSearch: validateFileSearch, component: () => { const user = useProtectedUser(); return <FileBrowser collection="shared" currentUserId={user.id} />; } });
const trashRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/trash", validateSearch: validateFileSearch, component: () => { const user = useProtectedUser(); return <FileBrowser collection="trash" currentUserId={user.id} />; } });
const searchRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/search", validateSearch: validateGlobalSearch, component: () => { const user = useProtectedUser(); const { q } = searchRoute.useSearch(); return <FileBrowser collection="search" currentUserId={user.id} query={q ?? ""} />; } });

const profileRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/settings/profile", component: () => { const user = useProtectedUser(); return <ProfileSettingsPage user={user} />; } });
const appearanceRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/settings/appearance", component: () => { const user = useProtectedUser(); return <AppearanceSettingsPage user={user} />; } });
const sessionsRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/settings/sessions", component: SessionsSettingsPage });
const developerRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/settings/developer", component: () => { const user = useProtectedUser(); return <DeveloperSettingsPage user={user} />; } });

const adminUsersRoute = createRoute({ getParentRoute: () => adminRoute, path: "/admin/users", component: AdminUsersPage });
const adminRequestsRoute = createRoute({ getParentRoute: () => adminRoute, path: "/admin/requests", component: AdminRequestsPage });
const adminStorageRoute = createRoute({ getParentRoute: () => adminRoute, path: "/admin/storage", component: AdminStoragePage });
const adminPoliciesRoute = createRoute({ getParentRoute: () => adminRoute, path: "/admin/policies", component: AdminPoliciesPage });
const adminAuditRoute = createRoute({ getParentRoute: () => adminRoute, path: "/admin/audit", component: AdminAuditPage });
const adminSettingsRoute = createRoute({ getParentRoute: () => adminRoute, path: "/admin/settings", component: AdminSettingsPage });

const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: () => <Navigate to="/files" replace /> });

const routeTree = rootRoute.addChildren([
  indexRoute,
  setupRoute,
  signInRoute,
  requestAccessRoute,
  redeemRoute,
  publicRoute,
  protectedRoute.addChildren([
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
    adminRoute.addChildren([
      adminUsersRoute,
      adminRequestsRoute,
      adminStorageRoute,
      adminPoliciesRoute,
      adminAuditRoute,
      adminSettingsRoute,
    ]),
  ]),
]);

export const router = createRouter({ routeTree, defaultPreload: "intent", defaultPreloadStaleTime: 0 });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
