import { QueryClient } from "@tanstack/react-query";
import { createRootRoute, createRoute, createRouter, Link, Navigate, Outlet } from "@tanstack/react-router";
import { useEffect, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { ApiError, api } from "../api/client";
import { AppShell } from "../components/AppShell";
import { ArcaMark } from "../components/ArcaMark";
import { Button, ErrorState, LoadingState } from "../components/Primitives";
import { UploadProvider } from "../features/uploads/UploadManager";
import { FileBrowser } from "../features/files/FileViews";
import { PublicPage, RedeemPage, RequestAccessPage, SetupPage, SignInPage } from "../pages/AuthPages";
import { AppearanceSettingsPage, DeveloperSettingsPage, ProfileSettingsPage, SessionsSettingsPage } from "../pages/SettingsPages";
import { AdminAuditPage, AdminPoliciesPage, AdminRequestsPage, AdminSettingsPage, AdminStoragePage, AdminUsersPage } from "../pages/AdminPages";
import { useAppearance } from "./appearance";

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
  return <Outlet />;
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

const filesRoute = createRoute({ getParentRoute: () => rootRoute, path: "/files", validateSearch: (search: Record<string, unknown>) => ({ view: search.view === "grid" ? "grid" as const : "list" as const, sort: typeof search.sort === "string" ? search.sort : "name", order: search.order === "desc" ? "desc" as const : "asc" as const }), component: () => <ProtectedPage>{() => <FileBrowser collection="files" />}</ProtectedPage> });
const folderRoute = createRoute({ getParentRoute: () => rootRoute, path: "/files/$folderId", validateSearch: filesRoute.options.validateSearch, component: () => { const { folderId } = folderRoute.useParams(); return <ProtectedPage>{() => <FileBrowser collection="files" folderId={folderId} />}</ProtectedPage>; } });
const recentRoute = createRoute({ getParentRoute: () => rootRoute, path: "/recent", validateSearch: filesRoute.options.validateSearch, component: () => <ProtectedPage>{() => <FileBrowser collection="recent" />}</ProtectedPage> });
const starredRoute = createRoute({ getParentRoute: () => rootRoute, path: "/starred", validateSearch: filesRoute.options.validateSearch, component: () => <ProtectedPage>{() => <FileBrowser collection="favorites" />}</ProtectedPage> });
const sharedRoute = createRoute({ getParentRoute: () => rootRoute, path: "/shared", validateSearch: filesRoute.options.validateSearch, component: () => <ProtectedPage>{() => <FileBrowser collection="shared" />}</ProtectedPage> });
const trashRoute = createRoute({ getParentRoute: () => rootRoute, path: "/trash", validateSearch: filesRoute.options.validateSearch, component: () => <ProtectedPage>{() => <FileBrowser collection="trash" />}</ProtectedPage> });
const searchRoute = createRoute({ getParentRoute: () => rootRoute, path: "/search", validateSearch: (search: Record<string, unknown>) => ({ q: typeof search.q === "string" ? search.q : "", view: search.view === "grid" ? "grid" as const : "list" as const, sort: typeof search.sort === "string" ? search.sort : "name", order: search.order === "desc" ? "desc" as const : "asc" as const }), component: () => { const { q } = searchRoute.useSearch(); return <ProtectedPage>{() => <FileBrowser collection="search" query={q} />}</ProtectedPage>; } });

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
