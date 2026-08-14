import { useQueryClient } from "@tanstack/react-query";
import { AlertCircle, Check, ChevronDown, CirclePause, LoaderCircle, Pause, Play, RotateCcw, X } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { UploadItem } from "../../api/types";
import { api, getCsrfToken } from "../../api/client";
import { formatBytes } from "../../lib";
import { Button, IconButton } from "../../components/Primitives";

const CHUNK_SIZE = 8 * 1024 * 1024;
const MAX_CONCURRENT = 3;
const DB_NAME = "arca-uploads";
const STORE_NAME = "sessions";

interface StoredUpload {
  id: string;
  name: string;
  size: number;
  offset: number;
  location: string;
  parentId: string | null;
  updatedAt: number;
}

interface UploadRecord extends UploadItem {
  file?: File | undefined;
  location?: string | undefined;
  parentId: string | null;
  controller?: AbortController | undefined;
  conflictMode?: "fail" | "keep_both" | "replace";
  replaceNodeId?: string | undefined;
  replaceRevision?: number | undefined;
}

interface UploadContextValue {
  uploads: UploadItem[];
  addFiles: (files: File[], parentId: string | null) => void;
  addFolderTree: (files: File[], parentId: string | null) => Promise<void>;
  pause: (id: string) => void;
  resume: (id: string) => void;
  cancel: (id: string) => void;
  retry: (id: string) => void;
  resolveConflict: (id: string, mode: "keep_both" | "replace") => Promise<void>;
  clearFinished: () => void;
}

const UploadContext = createContext<UploadContextValue | null>(null);

function openUploadDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) database.createObjectStore(STORE_NAME, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function listStoredUploads(): Promise<StoredUpload[]> {
  try {
    const database = await openUploadDb();
    return await new Promise((resolve, reject) => {
      const request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).getAll();
      request.onsuccess = () => resolve(request.result as StoredUpload[]);
      request.onerror = () => reject(request.error);
    });
  } catch {
    return [];
  }
}

async function saveStoredUpload(upload: StoredUpload): Promise<void> {
  try {
    const database = await openUploadDb();
    await new Promise<void>((resolve, reject) => {
      const request = database.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).put(upload);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch {
    // Upload still works when private browsing blocks IndexedDB; it simply cannot resume after reload.
  }
}

async function removeStoredUpload(id: string): Promise<void> {
  try {
    const database = await openUploadDb();
    await new Promise<void>((resolve, reject) => {
      const request = database.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).delete(id);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch {
    // Best-effort cleanup.
  }
}

function encodeMetadata(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function csrfHeader(): Record<string, string> {
  const value = getCsrfToken();
  return value ? { "X-CSRF-Token": value } : {};
}

export function UploadProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [records, setRecords] = useState<UploadRecord[]>([]);
  const recordsRef = useRef(records);
  recordsRef.current = records;

  const patchRecord = useCallback((id: string, patch: Partial<UploadRecord>) => {
    setRecords((current) => current.map((record) => record.id === id ? { ...record, ...patch } : record));
  }, []);

  useEffect(() => {
    void listStoredUploads().then((stored) => {
      setRecords((current) => {
        const existing = new Set(current.map((item) => item.id));
        return [
          ...current,
          ...stored.filter((item) => !existing.has(item.id)).map((item): UploadRecord => ({
            id: item.id,
            name: item.name,
            size: item.size,
            offset: item.offset,
            progress: item.size ? item.offset / item.size : 0,
            state: "paused",
            error: "Choose this file again to continue after the browser restart.",
            location: item.location,
            parentId: item.parentId,
          })),
        ];
      });
    });
  }, []);

  const runUpload = useCallback(async (upload: UploadRecord) => {
    if (!upload.file) {
      patchRecord(upload.id, { state: "paused", error: "Choose this file again to continue." });
      return;
    }
    const controller = new AbortController();
    patchRecord(upload.id, { state: "uploading", controller, error: undefined });
    let location = upload.location;
    let offset = upload.offset;
    try {
      if (!location) {
        const metadata = [
          `filename ${encodeMetadata(upload.name)}`,
          ...(upload.parentId ? [`parent_id ${encodeMetadata(upload.parentId)}`] : []),
          `conflict ${encodeMetadata(upload.conflictMode ?? "fail")}`,
          ...(upload.replaceNodeId ? [`replace_node_id ${encodeMetadata(upload.replaceNodeId)}`] : []),
          ...(upload.replaceRevision ? [`replace_revision ${encodeMetadata(String(upload.replaceRevision))}`] : []),
        ].join(",");
        const response = await fetch("/api/v1/uploads", {
          method: "POST",
          credentials: "same-origin",
          signal: controller.signal,
          headers: {
            ...csrfHeader(),
            "Tus-Resumable": "1.0.0",
            "Upload-Length": String(upload.size),
            "Upload-Metadata": metadata,
            "Idempotency-Key": crypto.randomUUID(),
          },
        });
        if (response.status === 409) {
          patchRecord(upload.id, { state: "conflict", error: "A file or folder with this name already exists." });
          return;
        }
        if (!response.ok) throw new Error(`Upload could not start (${response.status}).`);
        const returnedLocation = response.headers.get("Location");
        if (!returnedLocation) throw new Error("The server did not return an upload location.");
        location = new URL(returnedLocation, window.location.origin).toString();
        const parts = new URL(location).pathname.split("/");
        const serverId = parts.at(-1) || upload.id;
        if (serverId !== upload.id) {
          await removeStoredUpload(upload.id);
        }
        patchRecord(upload.id, { location });
      }

      await saveStoredUpload({ id: upload.id, name: upload.name, size: upload.size, offset, location, parentId: upload.parentId, updatedAt: Date.now() });
      while (offset < upload.size) {
        const current = recordsRef.current.find((item) => item.id === upload.id);
        if (!current || current.state === "paused" || current.state === "cancelled") return;
        const end = Math.min(offset + CHUNK_SIZE, upload.size);
        const response = await fetch(location, {
          method: "PATCH",
          body: upload.file.slice(offset, end),
          credentials: "same-origin",
          signal: controller.signal,
          headers: {
            ...csrfHeader(),
            "Content-Type": "application/offset+octet-stream",
            "Tus-Resumable": "1.0.0",
            "Upload-Offset": String(offset),
          },
        });
        if (response.status === 409) {
          const head = await fetch(location, { method: "HEAD", credentials: "same-origin", headers: { "Tus-Resumable": "1.0.0" } });
          const serverOffset = Number(head.headers.get("Upload-Offset"));
          if (!head.ok || !Number.isFinite(serverOffset)) throw new Error("The upload position could not be reconciled.");
          offset = serverOffset;
          continue;
        }
        if (!response.ok) throw new Error(`Upload interrupted (${response.status}).`);
        offset = Number(response.headers.get("Upload-Offset") ?? end);
        patchRecord(upload.id, { offset, progress: upload.size ? offset / upload.size : 1, state: offset === upload.size ? "finalizing" : "uploading" });
        await saveStoredUpload({ id: upload.id, name: upload.name, size: upload.size, offset, location, parentId: upload.parentId, updatedAt: Date.now() });
      }
      patchRecord(upload.id, { offset: upload.size, progress: 1, state: "completed", controller: undefined });
      await removeStoredUpload(upload.id);
      await queryClient.invalidateQueries({ queryKey: ["nodes"] });
      await queryClient.invalidateQueries({ queryKey: ["session"] });
    } catch (error) {
      if (controller.signal.aborted) return;
      patchRecord(upload.id, { state: "failed", controller: undefined, error: error instanceof Error ? error.message : "Upload interrupted." });
    }
  }, [patchRecord, queryClient]);

  useEffect(() => {
    const active = records.filter((upload) => upload.state === "uploading" || upload.state === "finalizing").length;
    const queued = records.filter((upload) => upload.state === "queued").slice(0, Math.max(0, MAX_CONCURRENT - active));
    for (const upload of queued) void runUpload(upload);
  }, [records, runUpload]);

  const addFiles = useCallback((files: File[], parentId: string | null) => {
    const next = files.map((file): UploadRecord => ({
      id: crypto.randomUUID(),
      name: file.name,
      size: file.size,
      offset: 0,
      progress: 0,
      state: "queued",
      file,
      parentId,
    }));
    setRecords((current) => [...next, ...current]);
  }, []);

  const addFolderTree = useCallback(async (files: File[], parentId: string | null) => {
    const paths = files.map((file) => ({ file, parts: (file.webkitRelativePath || file.name).split("/").filter(Boolean) }));
    const directoryPaths = new Set<string>();
    for (const item of paths) {
      for (let depth = 1; depth < item.parts.length; depth += 1) directoryPaths.add(item.parts.slice(0, depth).join("/"));
    }
    const resolved = new Map<string, string | null>([["", parentId]]);
    try {
      for (const directoryPath of [...directoryPaths].sort((left, right) => left.split("/").length - right.split("/").length)) {
        const parts = directoryPath.split("/");
        const name = parts.at(-1) ?? "Folder";
        const parentPath = parts.slice(0, -1).join("/");
        const directoryParent = resolved.get(parentPath) ?? parentId;
        try {
          const folder = await api.createFolder({ parentId: directoryParent, name });
          resolved.set(directoryPath, folder.id);
        } catch {
          const listing = await api.nodes(directoryParent ? { parentId: directoryParent } : {});
          const existing = listing.items.find((node) => node.kind === "folder" && node.name.localeCompare(name, undefined, { sensitivity: "base" }) === 0);
          if (!existing) throw new Error(`The folder “${name}” could not be created.`);
          resolved.set(directoryPath, existing.id);
        }
      }
      const next = paths.map(({ file, parts }): UploadRecord => {
        const directoryPath = parts.slice(0, -1).join("/");
        return {
          id: crypto.randomUUID(),
          name: parts.at(-1) ?? file.name,
          size: file.size,
          offset: 0,
          progress: 0,
          state: "queued",
          file,
          parentId: resolved.get(directoryPath) ?? parentId,
        };
      });
      setRecords((current) => [...next, ...current]);
      await queryClient.invalidateQueries({ queryKey: ["nodes"] });
    } catch (error) {
      setRecords((current) => [{
        id: crypto.randomUUID(),
        name: paths[0]?.parts[0] ?? "Selected folder",
        size: paths.reduce((total, item) => total + item.file.size, 0),
        offset: 0,
        progress: 0,
        state: "failed",
        error: error instanceof Error ? error.message : "The folder tree could not be prepared.",
        parentId,
      }, ...current]);
    }
  }, [queryClient]);

  const value = useMemo<UploadContextValue>(() => ({
    uploads: records,
    addFiles,
    addFolderTree,
    pause: (id) => {
      const upload = recordsRef.current.find((record) => record.id === id);
      upload?.controller?.abort();
      patchRecord(id, { state: "paused", controller: undefined });
    },
    resume: (id) => patchRecord(id, { state: "queued", error: undefined }),
    retry: (id) => patchRecord(id, { state: "queued", error: undefined }),
    resolveConflict: async (id, mode) => {
      const upload = recordsRef.current.find((record) => record.id === id);
      if (!upload) return;
      if (mode === "keep_both") {
        patchRecord(id, { state: "queued", error: undefined, conflictMode: "keep_both" });
        return;
      }
      try {
        const listing = await api.nodes(upload.parentId ? { parentId: upload.parentId } : {});
        const existing = listing.items.find((node) => node.kind === "file" && node.name.localeCompare(upload.name, undefined, { sensitivity: "base" }) === 0);
        if (!existing) throw new Error("The existing item is a folder and cannot be replaced by a file.");
        patchRecord(id, { state: "queued", error: undefined, conflictMode: "replace", replaceNodeId: existing.id, replaceRevision: existing.revision });
      } catch (error) {
        patchRecord(id, { state: "failed", error: error instanceof Error ? error.message : "The existing file could not be replaced." });
      }
    },
    cancel: (id) => {
      const upload = recordsRef.current.find((record) => record.id === id);
      upload?.controller?.abort();
      if (upload?.location) {
        void fetch(upload.location, { method: "DELETE", credentials: "same-origin", headers: { ...csrfHeader(), "Tus-Resumable": "1.0.0" } });
      }
      patchRecord(id, { state: "cancelled", controller: undefined });
      void removeStoredUpload(id);
    },
    clearFinished: () => setRecords((current) => current.filter((record) => !["completed", "cancelled"].includes(record.state))),
  }), [addFiles, addFolderTree, patchRecord, records]);

  return <UploadContext.Provider value={value}>{children}</UploadContext.Provider>;
}

export function useUploads(): UploadContextValue {
  const context = useContext(UploadContext);
  if (!context) throw new Error("useUploads must be used inside UploadProvider");
  return context;
}

export function UploadTray() {
  const { uploads, pause, resume, retry, resolveConflict, cancel, clearFinished } = useUploads();
  const [collapsed, setCollapsed] = useState(false);
  if (uploads.length === 0) return null;
  const active = uploads.filter((upload) => ["queued", "uploading", "finalizing", "retrying"].includes(upload.state)).length;
  const complete = uploads.filter((upload) => upload.state === "completed").length;
  return (
    <motion.section className="upload-tray" initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} aria-label="Uploads">
      <button className="upload-tray__head" onClick={() => setCollapsed((value) => !value)} type="button">
        <span className="upload-tray__title">{active ? `${active} upload${active === 1 ? "" : "s"} in progress` : `${complete} upload${complete === 1 ? "" : "s"} complete`}</span>
        <ChevronDown className={collapsed ? "" : "rotate-180"} size={17} />
      </button>
      <AnimatePresence initial={false}>
        {!collapsed ? (
          <motion.div className="upload-tray__body" initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }}>
            {uploads.map((upload) => (
              <div className="upload-item" key={upload.id}>
                <span className={`upload-item__state upload-item__state--${upload.state}`}>
                  {upload.state === "completed" ? <Check size={15} /> : upload.state === "failed" ? <AlertCircle size={15} /> : upload.state === "paused" ? <CirclePause size={15} /> : <LoaderCircle className={upload.state === "uploading" || upload.state === "finalizing" ? "spin" : ""} size={15} />}
                </span>
                <div className="upload-item__main">
                  <div className="upload-item__line"><strong title={upload.name}>{upload.name}</strong><span>{formatBytes(upload.size)}</span></div>
                  <div className="upload-progress"><span style={{ width: `${Math.round(upload.progress * 100)}%` }} /></div>
                  <span className="upload-item__caption">{upload.error ?? (upload.state === "finalizing" ? "Securing in your vault…" : `${Math.round(upload.progress * 100)}%`)}</span>
                  {upload.state === "conflict" ? <span className="upload-conflict-actions"><button onClick={() => void resolveConflict(upload.id, "keep_both")} type="button">Keep both</button><button onClick={() => void resolveConflict(upload.id, "replace")} type="button">Replace</button></span> : null}
                </div>
                {upload.state === "uploading" ? <IconButton label="Pause upload" onClick={() => pause(upload.id)}><Pause size={15} /></IconButton> : null}
                {upload.state === "paused" ? <IconButton label="Resume upload" onClick={() => resume(upload.id)}><Play size={15} /></IconButton> : null}
                {upload.state === "failed" ? <IconButton label="Retry upload" onClick={() => retry(upload.id)}><RotateCcw size={15} /></IconButton> : null}
                {!['completed', 'cancelled'].includes(upload.state) ? <IconButton label="Cancel upload" onClick={() => cancel(upload.id)}><X size={15} /></IconButton> : null}
              </div>
            ))}
            {active === 0 ? <div className="upload-tray__footer"><Button variant="ghost" onClick={clearFinished}>Clear finished</Button></div> : null}
          </motion.div>
        ) : null}
      </AnimatePresence>
    </motion.section>
  );
}
