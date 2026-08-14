import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Archive,
  ArrowDownToLine,
  AudioLines,
  Box,
  Check,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  Code2,
  Copy,
  Ellipsis,
  Eye,
  File,
  FileImage,
  FileText,
  FileVideo,
  Folder,
  FolderInput,
  Grid2X2,
  Info,
  List,
  LockKeyhole,
  MoreHorizontal,
  Pencil,
  Plus,
  RotateCcw,
  SearchX,
  Share2,
  ShieldCheck,
  Star,
  Trash2,
  Upload,
  Users,
  X,
} from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, describeError } from "../../api/client";
import type { ArcaNode, NodePage, PublicBundle, SharePermission } from "../../api/types";
import { fileCategory, formatBytes, formatRelativeDate, safeDownloadName } from "../../lib";
import { Button, EmptyState, ErrorState, Field, IconButton, LoadingState, Modal, SkeletonRows, StatusPill } from "../../components/Primitives";
import { useUploads } from "../uploads/UploadManager";
import { supportSearch } from "./supportMode";

type Collection = "files" | "recent" | "favorites" | "shared" | "trash" | "search";
type ViewMode = "list" | "grid";
type DestinationOperation = { node: ArcaNode; mode: "move" | "copy" | "save-copy" };

const collectionCopy: Record<Collection, { title: string; subtitle: string; emptyTitle: string; emptyDescription: string }> = {
  files: { title: "My files", subtitle: "Everything in its place, ready when you are.", emptyTitle: "Your vault is ready", emptyDescription: "Upload a file or create a folder to start organizing your workspace." },
  recent: { title: "Recent", subtitle: "The things you’ve touched lately.", emptyTitle: "Nothing recent yet", emptyDescription: "Files you open or change will gather here." },
  favorites: { title: "Starred", subtitle: "A short path back to what matters.", emptyTitle: "No starred files", emptyDescription: "Star important files and folders to keep them close." },
  shared: { title: "Shared with me", subtitle: "Workspaces and files teammates have opened to you.", emptyTitle: "Nothing shared yet", emptyDescription: "Items shared directly with your username or email will appear here." },
  trash: { title: "Trash", subtitle: "Items stay here for 30 days before they are permanently removed.", emptyTitle: "Trash is empty", emptyDescription: "Deleted items will wait here before automatic cleanup." },
  search: { title: "Search", subtitle: "Results across everything you can access.", emptyTitle: "No matches", emptyDescription: "Try a shorter name, another type, or fewer filters." },
};

function FileIcon({ node, size = 20 }: { node: ArcaNode; size?: number }) {
  if (node.kind === "folder") return <Folder className="file-icon file-icon--folder" fill="currentColor" size={size} strokeWidth={1.6} />;
  const category = fileCategory(node.mimeType, node.name);
  if (category === "image") return <FileImage className="file-icon file-icon--image" size={size} />;
  if (category === "video") return <FileVideo className="file-icon file-icon--video" size={size} />;
  if (category === "audio") return <AudioLines className="file-icon file-icon--audio" size={size} />;
  if (category === "pdf") return <FileText className="file-icon file-icon--pdf" size={size} />;
  if (category === "archive") return <Archive className="file-icon file-icon--archive" size={size} />;
  if (category === "code") return <Code2 className="file-icon file-icon--code" size={size} />;
  if (category === "text") return <FileText className="file-icon file-icon--text" size={size} />;
  return <File className="file-icon" size={size} />;
}

function NodeMenu({ node, collection, readOnly, canSaveCopy, onPreview, onDetails, onRename, onMove, onCopy, onSaveCopy, onShare, onTrash, onRestore, onPurge }: {
  node: ArcaNode;
  collection: Collection;
  readOnly: boolean;
  canSaveCopy: boolean;
  onPreview: () => void;
  onDetails: () => void;
  onRename: () => void;
  onMove: () => void;
  onCopy: () => void;
  onSaveCopy: () => void;
  onShare: () => void;
  onTrash: () => void;
  onRestore: () => void;
  onPurge: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild><IconButton label={`Actions for ${node.name}`}><MoreHorizontal size={17} /></IconButton></DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" className="dropdown" sideOffset={6}>
          <DropdownMenu.Item className="dropdown__item" onSelect={onPreview}><Eye size={16} />{node.kind === "folder" ? "Open" : "Preview"}</DropdownMenu.Item>
          {node.kind === "file" ? <DropdownMenu.Item asChild><a className="dropdown__item" download={safeDownloadName(node.name)} href={`/api/v1/files/${node.id}/content?download=1`}><ArrowDownToLine size={16} />Download</a></DropdownMenu.Item> : null}
          <DropdownMenu.Item className="dropdown__item" onSelect={onDetails}><Info size={16} />Details</DropdownMenu.Item>
          {!readOnly && collection !== "trash" && node.capabilities.write ? <DropdownMenu.Item className="dropdown__item" onSelect={onRename}><Pencil size={16} />Rename</DropdownMenu.Item> : null}
          {!readOnly && collection !== "trash" && node.capabilities.write ? <DropdownMenu.Item className="dropdown__item" onSelect={onMove}><FolderInput size={16} />Move</DropdownMenu.Item> : null}
          {!readOnly && collection !== "trash" && node.capabilities.write ? <DropdownMenu.Item className="dropdown__item" onSelect={onCopy}><Copy size={16} />Make a copy</DropdownMenu.Item> : null}
          {!readOnly && canSaveCopy ? <DropdownMenu.Item className="dropdown__item" onSelect={onSaveCopy}><Box size={16} />Save a copy</DropdownMenu.Item> : null}
          {!readOnly && collection !== "trash" && node.capabilities.share ? <DropdownMenu.Item className="dropdown__item" onSelect={onShare}><Share2 size={16} />Share</DropdownMenu.Item> : null}
          {!readOnly && (collection === "trash" || node.capabilities.trash) ? <DropdownMenu.Separator className="dropdown__separator" /> : null}
          {!readOnly && collection === "trash" ? <DropdownMenu.Item className="dropdown__item" onSelect={onRestore}><RotateCcw size={16} />Restore</DropdownMenu.Item> : !readOnly && node.capabilities.trash ? <DropdownMenu.Item className="dropdown__item dropdown__item--danger" onSelect={onTrash}><Trash2 size={16} />Move to trash</DropdownMenu.Item> : null}
          {!readOnly && collection === "trash" && node.capabilities.purge ? <DropdownMenu.Item className="dropdown__item dropdown__item--danger" onSelect={onPurge}><X size={16} />Delete forever</DropdownMenu.Item> : null}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function NodeName({ node, onPreview, supportUserId }: { node: ArcaNode; onPreview: () => void; supportUserId?: string | null | undefined }) {
  if (node.kind === "folder") return <Link className="node-name" to="/files/$folderId" params={{ folderId: node.id }} search={supportSearch(supportUserId)}>{node.name}</Link>;
  return <button className="node-name" onClick={onPreview} type="button">{node.name}</button>;
}

function FileList({
  nodes,
  collection,
  selected,
  onSelect,
  onPreview,
  onDetails,
  onRename,
  onMove,
  onCopy,
  onSaveCopy,
  onShare,
  onTrash,
  onRestore,
  onPurge,
  readOnly,
  supportUserId,
  currentUserId,
}: {
  nodes: ArcaNode[];
  collection: Collection;
  selected: Set<string>;
  onSelect: (id: string, selected: boolean) => void;
  onPreview: (node: ArcaNode) => void;
  onDetails: (node: ArcaNode) => void;
  onRename: (node: ArcaNode) => void;
  onMove: (node: ArcaNode) => void;
  onCopy: (node: ArcaNode) => void;
  onSaveCopy: (node: ArcaNode) => void;
  onShare: (node: ArcaNode) => void;
  onTrash: (node: ArcaNode) => void;
  onRestore: (node: ArcaNode) => void;
  onPurge: (node: ArcaNode) => void;
  readOnly: boolean;
  supportUserId?: string | null;
  currentUserId: string;
}) {
  return (
    <div className="file-table" role="grid" aria-label="Files and folders">
      <div className="file-table__head" role="row">
        <span aria-hidden="true" />
        <span>Name</span>
        <span>Owner</span>
        <span>Modified</span>
        <span>Size</span>
        <span aria-label="Actions" />
      </div>
      <AnimatePresence initial={false}>
        {nodes.map((node) => {
          const checked = selected.has(node.id);
          let holdTimer: number | undefined;
          return (
            <motion.div
              animate={{ opacity: 1, y: 0 }}
              className={`file-row ${checked ? "file-row--selected" : ""}`}
              exit={{ opacity: 0, height: 0 }}
              initial={{ opacity: 0, y: 4 }}
              key={node.id}
              layout
              onDoubleClick={() => onPreview(node)}
              onPointerCancel={() => window.clearTimeout(holdTimer)}
              onPointerDown={(event) => { if (event.pointerType === "touch") holdTimer = window.setTimeout(() => onSelect(node.id, true), 480); }}
              onPointerUp={() => window.clearTimeout(holdTimer)}
              role="row"
            >
              <label className="check"><input aria-label={`Select ${node.name}`} checked={checked} onChange={(event) => onSelect(node.id, event.target.checked)} type="checkbox" /><span><Check size={12} /></span></label>
              <div className="file-row__name" role="gridcell"><FileIcon node={node} /><NodeName node={node} onPreview={() => onPreview(node)} supportUserId={supportUserId} />{node.shared ? <Share2 aria-label="Shared" className="shared-mark" size={13} /> : null}</div>
              <span className="file-row__owner" role="gridcell">{node.owner.displayName || node.owner.username || "You"}</span>
              <span role="gridcell">{formatRelativeDate(node.updatedAt)}</span>
              <span role="gridcell">{node.kind === "folder" ? "—" : formatBytes(node.sizeBytes)}</span>
              <span role="gridcell"><NodeMenu canSaveCopy={node.kind === "file" && collection !== "trash" && (collection === "shared" || Boolean(node.owner.id && node.owner.id !== currentUserId))} collection={collection} node={node} onCopy={() => onCopy(node)} onDetails={() => onDetails(node)} onMove={() => onMove(node)} onPreview={() => onPreview(node)} onPurge={() => onPurge(node)} onRename={() => onRename(node)} onRestore={() => onRestore(node)} onSaveCopy={() => onSaveCopy(node)} onShare={() => onShare(node)} onTrash={() => onTrash(node)} readOnly={readOnly} /></span>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}

function FileGrid({ nodes, collection, selected, onSelect, onPreview, onDetails, onRename, onMove, onCopy, onSaveCopy, onShare, onTrash, onRestore, onPurge, readOnly, supportUserId, currentUserId }: Parameters<typeof FileList>[0]) {
  return (
    <div className="file-grid" role="grid" aria-label="Files and folders">
      {nodes.map((node) => {
        const checked = selected.has(node.id);
        let holdTimer: number | undefined;
        return (
          <motion.article className={`file-card ${checked ? "file-card--selected" : ""}`} initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} key={node.id} onDoubleClick={() => onPreview(node)} onPointerCancel={() => window.clearTimeout(holdTimer)} onPointerDown={(event) => { if (event.pointerType === "touch") holdTimer = window.setTimeout(() => onSelect(node.id, true), 480); }} onPointerUp={() => window.clearTimeout(holdTimer)} role="gridcell">
            <div className="file-card__top"><label className="check"><input aria-label={`Select ${node.name}`} checked={checked} onChange={(event) => onSelect(node.id, event.target.checked)} type="checkbox" /><span><Check size={12} /></span></label><NodeMenu canSaveCopy={node.kind === "file" && collection !== "trash" && (collection === "shared" || Boolean(node.owner.id && node.owner.id !== currentUserId))} collection={collection} node={node} onCopy={() => onCopy(node)} onDetails={() => onDetails(node)} onMove={() => onMove(node)} onPreview={() => onPreview(node)} onPurge={() => onPurge(node)} onRename={() => onRename(node)} onRestore={() => onRestore(node)} onSaveCopy={() => onSaveCopy(node)} onShare={() => onShare(node)} onTrash={() => onTrash(node)} readOnly={readOnly} /></div>
            <button className="file-card__preview" onClick={() => onPreview(node)} type="button"><span className="file-card__arch"><FileIcon node={node} size={36} /></span></button>
            <div className="file-card__copy"><NodeName node={node} onPreview={() => onPreview(node)} supportUserId={supportUserId} /><span>{node.kind === "folder" ? formatRelativeDate(node.updatedAt) : `${formatBytes(node.sizeBytes)} · ${formatRelativeDate(node.updatedAt)}`}</span></div>
          </motion.article>
        );
      })}
    </div>
  );
}

function PreviewDialog({ node, onClose, supportUserId }: { node: ArcaNode | null; onClose: () => void; supportUserId?: string | null | undefined }) {
  const category = node ? fileCategory(node.mimeType, node.name) : "generic";
  const canInline = ["image", "video", "audio", "pdf", "text", "code"].includes(category);
  const text = useQuery({
    queryKey: ["preview-text", node?.id],
    queryFn: async () => {
      if (!node) return "";
      const response = await fetch(`/api/v1/files/${node.id}/content?preview=1`, { credentials: "same-origin" });
      if (!response.ok) throw new Error("Preview could not be loaded.");
      return response.text();
    },
    enabled: Boolean(node && (category === "text" || category === "code")),
  });
  if (!node) return null;
  if (node.kind === "folder") {
    return <Modal open onOpenChange={(open) => { if (!open) onClose(); }} title={node.name}><EmptyState title="This is a folder" description="Open it to browse its contents." action={<Link className="button button--primary" params={{ folderId: node.id }} search={supportSearch(supportUserId)} to="/files/$folderId">Open folder</Link>} /></Modal>;
  }
  return (
    <Modal open onOpenChange={(open) => { if (!open) onClose(); }} title={node.name} description={`${formatBytes(node.sizeBytes)} · ${node.mimeType ?? "File"}`} wide>
      <div className="preview">
        {category === "image" ? <img alt={node.name} src={`/api/v1/files/${node.id}/content?preview=1`} /> : null}
        {category === "video" ? <video controls src={`/api/v1/files/${node.id}/content?preview=1`} /> : null}
        {category === "audio" ? <div className="audio-preview"><span className="file-card__arch"><AudioLines size={42} /></span><audio controls src={`/api/v1/files/${node.id}/content?preview=1`} /></div> : null}
        {category === "pdf" ? <iframe sandbox="allow-same-origin" src={`/api/v1/files/${node.id}/content?preview=1`} title={`Preview of ${node.name}`} /> : null}
        {category === "text" || category === "code" ? text.isPending ? <LoadingState label="Loading preview…" compact /> : text.isError ? <ErrorState error={text.error} onRetry={() => void text.refetch()} /> : <pre><code>{text.data}</code></pre> : null}
        {!canInline ? <EmptyState icon="archive" title="Preview isn’t available" description="This file type is kept download-only to protect your browser." action={<a className="button button--primary" download={safeDownloadName(node.name)} href={`/api/v1/files/${node.id}/content?download=1`}><ArrowDownToLine size={17} />Download file</a>} /> : null}
      </div>
      <div className="preview-actions"><a className="button button--secondary" download={safeDownloadName(node.name)} href={`/api/v1/files/${node.id}/content?download=1`}><ArrowDownToLine size={17} />Download</a></div>
    </Modal>
  );
}

function DetailsPanel({ node, onClose }: { node: ArcaNode | null; onClose: () => void }) {
  const versions = useQuery({ queryKey: ["versions", node?.id], queryFn: () => api.versions(node?.id ?? ""), enabled: Boolean(node?.id && node.kind === "file") });
  return (
    <AnimatePresence>
      {node ? (
        <motion.aside className="details-panel" initial={{ x: 32, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 32, opacity: 0 }} aria-label={`Details for ${node.name}`}>
          <div className="details-panel__head"><div><span className="eyebrow">Details</span><h2>{node.name}</h2></div><IconButton label="Close details" onClick={onClose}><X size={18} /></IconButton></div>
          <div className="details-hero"><span className="file-card__arch"><FileIcon node={node} size={38} /></span></div>
          <dl className="details-list"><div><dt>Type</dt><dd>{node.kind === "folder" ? "Folder" : node.mimeType ?? "File"}</dd></div><div><dt>Owner</dt><dd>{node.owner.displayName || node.owner.username || "You"}</dd></div><div><dt>Size</dt><dd>{node.kind === "folder" ? "—" : formatBytes(node.sizeBytes)}</dd></div><div><dt>Modified</dt><dd>{formatRelativeDate(node.updatedAt)}</dd></div><div><dt>Created</dt><dd>{formatRelativeDate(node.createdAt)}</dd></div><div><dt>Status</dt><dd>{node.shared ? "Shared" : "Private"}</dd></div></dl>
          {node.kind === "file" ? <div className="versions"><h3>Version history</h3>{versions.isPending ? <LoadingState compact label="Loading history…" /> : versions.data?.length ? versions.data.map((version) => <div className="version" key={version.id}><span>v{version.sequence}</span><div><strong>{formatBytes(version.sizeBytes)}</strong><small>{formatRelativeDate(version.createdAt)}</small></div></div>) : <p className="muted">No earlier versions.</p>}</div> : null}
        </motion.aside>
      ) : null}
    </AnimatePresence>
  );
}

function RenameDialog({ node, onClose }: { node: ArcaNode | null; onClose: () => void }) {
  const [name, setName] = useState(node?.name ?? "");
  const queryClient = useQueryClient();
  useEffect(() => setName(node?.name ?? ""), [node]);
  const rename = useMutation({ mutationFn: () => api.renameNode(node?.id ?? "", name.trim(), node?.revision ?? 1), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["nodes"] }); onClose(); } });
  return <Modal open={Boolean(node)} onOpenChange={(open) => { if (!open) onClose(); }} title={`Rename ${node?.kind ?? "item"}`} footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button disabled={!name.trim() || rename.isPending} onClick={() => rename.mutate()}>{rename.isPending ? "Renaming…" : "Rename"}</Button></>}><Field label="Name" error={rename.error ? describeError(rename.error) : undefined}><input autoFocus onFocus={(event) => { const dot = event.currentTarget.value.lastIndexOf("."); event.currentTarget.setSelectionRange(0, node?.kind === "file" && dot > 0 ? dot : event.currentTarget.value.length); }} onChange={(event) => setName(event.target.value)} value={name} /></Field></Modal>;
}

function ShareDialog({ nodes, onClose }: { nodes: ArcaNode[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<"people" | "public">("people");
  const [recipient, setRecipient] = useState("");
  const [permission, setPermission] = useState<SharePermission>("viewer");
  const [ttl, setTtl] = useState(10);
  const [redemptions, setRedemptions] = useState(3);
  const [publicCode, setPublicCode] = useState<string | null>(null);
  const internal = useMutation({
    mutationFn: () => api.createShare({ rootIds: nodes.map((node) => node.id), recipients: [recipient.trim()], permission, allowEditorUploads: false }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["shares"] }); onClose(); },
  });
  const publicShare = useMutation({
    mutationFn: () => api.createPublicShare({ rootIds: nodes.map((node) => node.id), ttlMinutes: ttl, redemptionLimit: redemptions }),
    onSuccess: (share) => setPublicCode(share.code ?? null),
  });
  const hasFolder = nodes.some((node) => node.kind === "folder");
  const selectedLabel = nodes.length === 1 ? nodes[0]?.name ?? "item" : `${nodes.length} selected items`;
  return (
    <Modal open={nodes.length > 0} onOpenChange={(open) => { if (!open) onClose(); }} title={`Share ${selectedLabel}`} description="Choose who can open this bundle and for how long.">
      <div className="tabs" role="tablist"><button aria-selected={tab === "people"} className={tab === "people" ? "active" : ""} onClick={() => setTab("people")} role="tab" type="button"><Users size={16} />People</button><button aria-selected={tab === "public"} className={tab === "public" ? "active" : ""} onClick={() => setTab("public")} role="tab" type="button"><LockKeyhole size={16} />Public code</button></div>
      {tab === "people" ? (
        <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); internal.mutate(); }}>
          <Field hint="The person must already have an active account on this Arca." label="Username or email"><input autoFocus onChange={(event) => setRecipient(event.target.value)} placeholder="marie or marie@company.com" required value={recipient} /></Field>
          <Field label="Permission"><select onChange={(event) => setPermission(event.target.value as SharePermission)} value={permission}><option value="viewer">Viewer — can open and download</option><option value="editor">Editor — can organize and update</option></select></Field>
          {permission === "editor" ? <div className="notice"><ShieldCheck size={18} /><p>Editor uploads stay disabled by default. You can enable a finite allowance from the share details later.</p></div> : null}
          {internal.error ? <p className="form-error">{describeError(internal.error)}</p> : null}
          <div className="dialog-actions"><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button disabled={!recipient.trim() || internal.isPending}>{internal.isPending ? "Sharing…" : "Share securely"}</Button></div>
        </form>
      ) : publicCode ? (
        <div className="public-code-result"><span className="eyebrow">Share this code once</span><strong>{publicCode}</strong><p>It expires in {ttl} minutes and works {redemptions} {redemptions === 1 ? "time" : "times"}. Arca cannot show it again.</p><Button onClick={() => void navigator.clipboard.writeText(publicCode)}><Copy size={16} />Copy code</Button></div>
      ) : (
        <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); publicShare.mutate(); }}>
          {hasFolder ? <div className="notice notice--warning"><CircleAlert size={18} /><p>This is a live folder share. Files added or replaced before expiry will become public too.</p></div> : null}
          <div className="form-grid"><Field label="Expires after"><select onChange={(event) => setTtl(Number(event.target.value))} value={ttl}>{[1, 5, 10, 20, 30].map((minutes) => <option key={minutes} value={minutes}>{minutes} minute{minutes === 1 ? "" : "s"}</option>)}</select></Field><Field label="Successful opens"><select onChange={(event) => setRedemptions(Number(event.target.value))} value={redemptions}>{Array.from({ length: 10 }, (_, index) => index + 1).map((count) => <option key={count} value={count}>{count}</option>)}</select></Field></div>
          <p className="muted">The five-digit code is never placed in a URL or stored in plaintext.</p>
          {publicShare.error ? <p className="form-error">{describeError(publicShare.error)}</p> : null}
          <div className="dialog-actions"><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button disabled={publicShare.isPending}>{publicShare.isPending ? "Creating…" : "Create temporary code"}</Button></div>
        </form>
      )}
    </Modal>
  );
}

function DestinationDialog({ operation, onClose }: { operation: DestinationOperation | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [path, setPath] = useState<Array<{ id: string | null; name: string }>>([{ id: null, name: "My files" }]);
  const [name, setName] = useState("");
  const [conflictMode, setConflictMode] = useState<"fail" | "keep_both">("keep_both");
  useEffect(() => {
    setPath([{ id: null, name: "My files" }]);
    setName(operation?.node.name ?? "");
    setConflictMode("keep_both");
  }, [operation]);
  const parentId = path.at(-1)?.id ?? null;
  const saveCopy = operation?.mode === "save-copy";
  const folders = useQuery({
    queryKey: ["destination-folders", operation?.mode, parentId],
    queryFn: () => api.nodes(parentId ? { parentId } : {}),
    enabled: Boolean(operation),
  });
  const transfer = useMutation({
    mutationFn: () => {
      if (!operation) throw new Error("Choose an item first.");
      if (operation.mode === "save-copy") return api.saveCopyNode(operation.node.id, { destinationId: parentId, name: name.trim(), conflictMode });
      if (operation.mode === "copy") return api.copyNode(operation.node.id, parentId, operation.node.revision);
      return api.moveNode(operation.node.id, parentId, operation.node.revision);
    },
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["nodes"] }); onClose(); },
  });
  const available = folders.data?.items.filter((node) => node.kind === "folder" && node.id !== operation?.node.id) ?? [];
  const actionLabel = saveCopy ? "Save here" : operation?.mode === "copy" ? "Copy here" : "Move here";
  return (
    <Modal
      open={Boolean(operation)}
      onOpenChange={(open) => { if (!open) onClose(); }}
      title={`${saveCopy ? "Save a copy of" : operation?.mode === "copy" ? "Copy" : "Move"} ${operation?.node.name ?? "item"}`}
      description={saveCopy ? "Choose where to store your private copy. It creates a recipient-owned blob and uses your quota." : "Choose a destination folder. Arca validates cycles and name conflicts before changing anything."}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button disabled={transfer.isPending || (saveCopy && !name.trim()) || (operation?.mode === "move" && operation.node.parentId === parentId)} onClick={() => transfer.mutate()}>{transfer.isPending ? "Working…" : actionLabel}</Button></>}
    >
      {saveCopy ? <div className="form-grid save-copy-options"><Field label="File name"><input maxLength={255} onChange={(event) => setName(event.target.value)} value={name} /></Field><Field label="If the name exists"><select onChange={(event) => setConflictMode(event.target.value as "fail" | "keep_both")} value={conflictMode}><option value="keep_both">Keep both</option><option value="fail">Stop without saving</option></select></Field></div> : null}
      <nav aria-label="Destination breadcrumb" className="destination-breadcrumbs">{path.map((crumb, index) => <span key={crumb.id ?? "root"}>{index ? <ChevronRight size={13} /> : null}<button onClick={() => setPath((current) => current.slice(0, index + 1))} type="button">{crumb.name}</button></span>)}</nav>
      <div className="destination-list">
        {folders.isPending ? <LoadingState compact label="Loading folders…" /> : folders.isError ? <ErrorState error={folders.error} onRetry={() => void folders.refetch()} /> : available.length ? available.map((folder) => <button key={folder.id} onClick={() => setPath((current) => [...current, { id: folder.id, name: folder.name }])} type="button"><Folder fill="currentColor" size={19} /><span>{folder.name}</span><ChevronRight size={15} /></button>) : <EmptyState title="No folders here" description="Choose this destination or go back up the path." />}
      </div>
      {transfer.error ? <p className="form-error">{describeError(transfer.error)}</p> : null}
    </Modal>
  );
}

function NewFolderDialog({ open, parentId, onClose }: { open: boolean; parentId: string | null; onClose: () => void }) {
  const [name, setName] = useState("");
  const queryClient = useQueryClient();
  const create = useMutation({ mutationFn: () => api.createFolder({ parentId, name: name.trim() }), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["nodes"] }); setName(""); onClose(); } });
  return <Modal open={open} onOpenChange={(value) => { if (!value) onClose(); }} title="New folder" description="Folders help keep projects and handoffs easy to find." footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button disabled={!name.trim() || create.isPending} onClick={() => create.mutate()}>{create.isPending ? "Creating…" : "Create folder"}</Button></>}><Field label="Folder name" error={create.error ? describeError(create.error) : undefined}><input autoFocus maxLength={255} onChange={(event) => setName(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && name.trim()) create.mutate(); }} placeholder="Project files" value={name} /></Field></Modal>;
}

function ConfirmDialog({ node, action, onClose, onConfirm, pending, error }: { node: ArcaNode | null; action: "trash" | "purge"; onClose: () => void; onConfirm: () => void; pending: boolean; error: unknown }) {
  const destructive = action === "purge";
  return <Modal open={Boolean(node)} onOpenChange={(open) => { if (!open) onClose(); }} title={destructive ? "Delete forever?" : "Move to trash?"} description={destructive ? "This cannot be undone. Historical versions may also become eligible for cleanup." : "You can restore this item from Trash for up to 30 days."} footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant={destructive ? "danger" : "primary"} disabled={pending} onClick={onConfirm}>{pending ? "Working…" : destructive ? "Delete forever" : "Move to trash"}</Button></>}><div className="confirm-item"><FileIcon node={node ?? ({ kind: "file" } as ArcaNode)} /><strong>{node?.name}</strong></div>{error ? <p className="form-error">{describeError(error)}</p> : null}</Modal>;
}

function Breadcrumbs({ page, collection, supportUserId }: { page: NodePage; collection: Collection; supportUserId?: string | null | undefined }) {
  if (collection !== "files") return null;
  const crumbs = page.breadcrumbs.length ? page.breadcrumbs : [{ id: null, name: "My files" }];
  return <nav aria-label="Breadcrumb" className="breadcrumbs">{crumbs.map((crumb, index) => <span key={crumb.id ?? "root"}>{index ? <ChevronRight size={14} /> : null}{index === crumbs.length - 1 ? <strong>{crumb.name}</strong> : crumb.id ? <Link to="/files/$folderId" params={{ folderId: crumb.id }} search={supportSearch(supportUserId)}>{crumb.name}</Link> : <Link to="/files" search={supportSearch(supportUserId)}>{crumb.name}</Link>}</span>)}</nav>;
}

function ManagedShares() {
  const queryClient = useQueryClient();
  const session = useQuery({ queryKey: ["session"], queryFn: api.session });
  const shares = useQuery({ queryKey: ["shares"], queryFn: api.shares });
  const publicShares = useQuery({ queryKey: ["public-shares"], queryFn: api.publicShares });
  const revokeInternal = useMutation({ mutationFn: api.revokeShare, onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["shares"] }) });
  const revokePublic = useMutation({ mutationFn: api.revokePublicShare, onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["public-shares"] }) });
  const owned = shares.data?.filter((share) => share.ownerId === session.data?.user?.id) ?? [];
  const temporary = publicShares.data ?? [];
  if (shares.isPending || publicShares.isPending) return <section className="managed-shares"><div className="managed-shares__head"><h2>Shares you manage</h2></div><LoadingState compact label="Loading active shares…" /></section>;
  if (!owned.length && !temporary.length) return null;
  return (
    <section className="managed-shares">
      <div className="managed-shares__head"><div><h2>Shares you manage</h2><p>Revoke access immediately or check temporary-code usage.</p></div></div>
      <div className="managed-share-list">
        {owned.map((share) => <div className="managed-share" key={share.id}><span className="managed-share__icon"><Users size={17} /></span><div><strong>{share.roots.map((node) => node.name).join(", ") || "Shared bundle"}</strong><span>{share.permission} · {share.recipients.map((recipient) => recipient.displayName || recipient.username).join(", ")}</span></div><StatusPill tone="accent">Internal</StatusPill><Button disabled={revokeInternal.isPending} onClick={() => revokeInternal.mutate(share.id)} variant="ghost">Revoke</Button></div>)}
        {temporary.map((share) => <div className="managed-share" key={share.id}><span className="managed-share__icon"><LockKeyhole size={17} /></span><div><strong>{share.roots.map((node) => node.name).join(", ") || "Public bundle"}</strong><span>{share.redemptionCount} of {share.redemptionLimit} opens · expires {formatRelativeDate(share.expiresAt)}</span></div><StatusPill tone={share.state === "active" ? "warning" : "neutral"}>{share.state}</StatusPill>{share.state === "active" ? <Button disabled={revokePublic.isPending} onClick={() => revokePublic.mutate(share.id)} variant="ghost">Revoke</Button> : <span />}</div>)}
      </div>
    </section>
  );
}

export function FileBrowser({ collection, currentUserId, folderId = null, query = "", supportUserId = null }: { collection: Collection; currentUserId: string; folderId?: string | null; query?: string; supportUserId?: string | null | undefined }) {
  const navigate = useNavigate();
  const routerSearch = useRouterState({ select: (state) => state.location.search as Record<string, unknown> });
  const view = routerSearch.view === "grid" ? "grid" : "list";
  const sort = typeof routerSearch.sort === "string" ? routerSearch.sort : "name";
  const order = routerSearch.order === "desc" ? "desc" : "asc";
  const readOnly = Boolean(supportUserId);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [preview, setPreview] = useState<ArcaNode | null>(null);
  const [details, setDetails] = useState<ArcaNode | null>(null);
  const [renaming, setRenaming] = useState<ArcaNode | null>(null);
  const [sharing, setSharing] = useState<ArcaNode[]>([]);
  const [destination, setDestination] = useState<DestinationOperation | null>(null);
  const [confirm, setConfirm] = useState<{ node: ArcaNode; action: "trash" | "purge" } | null>(null);
  const [newFolder, setNewFolder] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const { addFiles, addFolderTree } = useUploads();
  const queryClient = useQueryClient();
  const data = useQuery({
    queryKey: ["nodes", collection, folderId, query, sort, order, supportUserId],
    queryFn: () => collection === "files" ? api.nodes({ ...(folderId ? { parentId: folderId } : {}), ...(supportUserId ? { supportUserId } : {}), sort, order }) : collection === "search" ? api.search(query) : api.collection(collection, query),
  });
  const action = useMutation({
    mutationFn: async ({ node, kind }: { node: ArcaNode; kind: "trash" | "restore" | "purge" }) => {
      if (kind === "trash") return api.trashNode(node.id, node.revision);
      if (kind === "restore") return api.restoreNode(node.id, node.revision);
      return api.purgeNode(node.id, node.revision);
    },
    onSuccess: async () => { setConfirm(null); setSelected(new Set()); await queryClient.invalidateQueries({ queryKey: ["nodes"] }); },
  });
  const favorite = useMutation({ mutationFn: ({ node, next }: { node: ArcaNode; next: boolean }) => api.favoriteNode(node.id, next), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["nodes"] }) });

  useEffect(() => {
    const open = () => { if (!readOnly) setNewFolder(true); };
    window.addEventListener("arca:new-folder", open);
    folderInput.current?.setAttribute("webkitdirectory", "");
    folderInput.current?.setAttribute("directory", "");
    return () => window.removeEventListener("arca:new-folder", open);
  }, [readOnly]);

  useEffect(() => {
    if (!readOnly) return;
    setRenaming(null);
    setSharing([]);
    setDestination(null);
    setConfirm(null);
    setNewFolder(false);
    setDragActive(false);
  }, [readOnly]);

  const nodes = data.data?.items ?? [];
  const selectedNodes = nodes.filter((node) => selected.has(node.id));
  const updateUrlPreference = (key: "view" | "sort", value: string) => {
    const url = new URL(window.location.href);
    url.searchParams.set(key, value);
    window.history.replaceState(window.history.state, "", url);
    window.dispatchEvent(new PopStateEvent("popstate"));
  };
  const setView = (next: ViewMode) => updateUrlPreference("view", next);
  const toggleSelect = useCallback((id: string, checked: boolean) => setSelected((current) => { const next = new Set(current); if (checked) next.add(id); else next.delete(id); return next; }), []);
  const openNode = (node: ArcaNode) => node.kind === "folder" ? void navigate({ to: "/files/$folderId", params: { folderId: node.id }, search: supportSearch(supportUserId) }) : setPreview(node);
  const copy = collectionCopy[collection];
  const title = readOnly ? "Member files" : collection === "search" && query ? `Results for “${query}”` : copy.title;
  const subtitle = readOnly ? "Browse and inspect this vault without changing its contents." : copy.subtitle;

  useEffect(() => {
    const keyboard = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target?.matches("input, textarea, select, [contenteditable='true']")) return;
      if (event.key === "Escape") setSelected(new Set());
      if (selectedNodes.length === 1 && event.key === " ") { event.preventDefault(); openNode(selectedNodes[0]!); }
      if (!readOnly && selectedNodes.length === 1 && event.key === "F2" && selectedNodes[0]?.capabilities.write) { event.preventDefault(); setRenaming(selectedNodes[0]); }
      if (!readOnly && selectedNodes.length === 1 && event.key === "Delete" && selectedNodes[0]?.capabilities.trash) { event.preventDefault(); setConfirm({ node: selectedNodes[0], action: "trash" }); }
    };
    window.addEventListener("keydown", keyboard);
    return () => window.removeEventListener("keydown", keyboard);
  }, [readOnly, selectedNodes, supportUserId]);

  return (
    <div className={`files-layout ${details ? "files-layout--details" : ""}`}>
      <section
        className={`file-browser ${dragActive ? "file-browser--drag" : ""} ${readOnly ? "file-browser--read-only" : ""}`}
        onDragEnter={(event) => { if (!readOnly && collection === "files" && event.dataTransfer.types.includes("Files")) { event.preventDefault(); setDragActive(true); } }}
        onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragActive(false); }}
        onDragOver={(event) => { if (!readOnly && collection === "files") event.preventDefault(); }}
        onDrop={(event) => { if (!readOnly && collection === "files") { event.preventDefault(); setDragActive(false); const files = Array.from(event.dataTransfer.files); if (files.length) addFiles(files, folderId); } }}
      >
        {dragActive ? <div className="drop-overlay"><Upload size={25} /><strong>Drop files into this folder</strong><span>Uploads begin immediately and remain resumable.</span></div> : null}
        {data.data ? <Breadcrumbs collection={collection} page={data.data} supportUserId={supportUserId} /> : null}
        <div className="page-title-row"><div className="page-heading"><h1>{title}</h1><p>{subtitle}</p></div>{collection === "trash" ? <StatusPill tone="neutral">30-day retention</StatusPill> : null}</div>
        <div className="file-toolbar">
          {selected.size ? (
            <div className="selection-toolbar"><button className="selection-count" onClick={() => setSelected(new Set())} type="button"><X size={15} />{selected.size} selected</button>{!readOnly && selectedNodes.every((node) => node.capabilities.share) && collection !== "trash" ? <Button variant="secondary" onClick={() => setSharing(selectedNodes)}><Share2 size={16} />Share</Button> : null}{!readOnly && selectedNodes.length === 1 ? <Button variant="ghost" onClick={() => favorite.mutate({ node: selectedNodes[0]!, next: !selectedNodes[0]!.favorite })}><Star fill={selectedNodes[0]?.favorite ? "currentColor" : "none"} size={16} />{selectedNodes[0]?.favorite ? "Unstar" : "Star"}</Button> : null}</div>
          ) : (
            <div className="file-toolbar__primary">{readOnly ? <StatusPill tone="accent"><ShieldCheck size={12} />Read only</StatusPill> : collection === "files" ? <><Button onClick={() => fileInput.current?.click()}><Upload size={17} />Upload</Button><Button variant="secondary" onClick={() => setNewFolder(true)}><Plus size={17} />New folder</Button><Button className="desktop-folder-upload" variant="ghost" onClick={() => folderInput.current?.click()}><FolderInput size={17} />Upload folder</Button><input className="sr-only" multiple ref={fileInput} type="file" onChange={(event) => { const files = Array.from(event.target.files ?? []); if (files.length) addFiles(files, folderId); event.target.value = ""; }} /><input className="sr-only" multiple ref={folderInput} type="file" onChange={(event) => { const files = Array.from(event.target.files ?? []); if (files.length) void addFolderTree(files, folderId); event.target.value = ""; }} /></> : null}</div>
          )}
          <div className="file-toolbar__view">
            <label className="sort-select">Sort <select onChange={(event) => updateUrlPreference("sort", event.target.value)} value={sort}><option value="name">Name</option><option value="updated_at">Modified</option><option value="size_bytes">Size</option></select><ChevronDown size={14} /></label>
            <div className="segmented" aria-label="View style"><IconButton className={view === "list" ? "active" : ""} label="List view" onClick={() => setView("list")}><List size={17} /></IconButton><IconButton className={view === "grid" ? "active" : ""} label="Grid view" onClick={() => setView("grid")}><Grid2X2 size={17} /></IconButton></div>
          </div>
        </div>
        {data.isPending ? <SkeletonRows /> : data.isError ? <ErrorState error={data.error} onRetry={() => void data.refetch()} /> : nodes.length === 0 ? <EmptyState icon={collection === "trash" ? "archive" : "empty"} title={readOnly ? "This vault is empty" : copy.emptyTitle} description={readOnly ? "There are no files or folders to inspect here." : copy.emptyDescription} action={!readOnly && collection === "files" ? <Button onClick={() => fileInput.current?.click()}><Upload size={17} />Upload your first file</Button> : undefined} /> : view === "grid" ? (
          <FileGrid collection={collection} currentUserId={currentUserId} nodes={nodes} onCopy={(node) => setDestination({ node, mode: "copy" })} onDetails={setDetails} onMove={(node) => setDestination({ node, mode: "move" })} onPreview={openNode} onPurge={(node) => setConfirm({ node, action: "purge" })} onRename={setRenaming} onRestore={(node) => action.mutate({ node, kind: "restore" })} onSaveCopy={(node) => setDestination({ node, mode: "save-copy" })} onSelect={toggleSelect} onShare={(node) => setSharing([node])} onTrash={(node) => setConfirm({ node, action: "trash" })} readOnly={readOnly} selected={selected} supportUserId={supportUserId} />
        ) : (
          <FileList collection={collection} currentUserId={currentUserId} nodes={nodes} onCopy={(node) => setDestination({ node, mode: "copy" })} onDetails={setDetails} onMove={(node) => setDestination({ node, mode: "move" })} onPreview={openNode} onPurge={(node) => setConfirm({ node, action: "purge" })} onRename={setRenaming} onRestore={(node) => action.mutate({ node, kind: "restore" })} onSaveCopy={(node) => setDestination({ node, mode: "save-copy" })} onSelect={toggleSelect} onShare={(node) => setSharing([node])} onTrash={(node) => setConfirm({ node, action: "trash" })} readOnly={readOnly} selected={selected} supportUserId={supportUserId} />
        )}
        {collection === "shared" ? <ManagedShares /> : null}
      </section>
      <DetailsPanel node={details} onClose={() => setDetails(null)} />
      <PreviewDialog node={preview} onClose={() => setPreview(null)} supportUserId={supportUserId} />
      {!readOnly ? <><RenameDialog node={renaming} onClose={() => setRenaming(null)} /><ShareDialog nodes={sharing} onClose={() => setSharing([])} /><DestinationDialog onClose={() => setDestination(null)} operation={destination} /><NewFolderDialog onClose={() => setNewFolder(false)} open={newFolder} parentId={folderId} /><ConfirmDialog action={confirm?.action ?? "trash"} error={action.error} node={confirm?.node ?? null} onClose={() => setConfirm(null)} onConfirm={() => { if (confirm) action.mutate({ node: confirm.node, kind: confirm.action }); }} pending={action.isPending} /></> : null}
    </div>
  );
}

export function PublicFiles({ bundle }: { bundle: PublicBundle }) {
  const items = bundle.items.length ? bundle.items : bundle.roots;
  if (!items.length) return <EmptyState icon="archive" title="This bundle is empty" description="The sender may have moved or removed its contents." />;
  return (
    <div className="public-files">
      {items.map((node) => <div className="public-file" key={node.id}><span className="public-file__icon"><FileIcon node={node} size={22} /></span><div><strong>{node.name}</strong><span>{node.kind === "folder" ? "Folder" : formatBytes(node.sizeBytes)}</span></div>{node.kind === "file" ? <a aria-label={`Download ${node.name}`} className="icon-button" download={safeDownloadName(node.name)} href={`/api/v1/public/files/${node.id}/content`}><ArrowDownToLine size={18} /></a> : <StatusPill>Folder</StatusPill>}</div>)}
    </div>
  );
}
