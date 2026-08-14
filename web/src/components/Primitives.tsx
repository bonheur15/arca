import * as Dialog from "@radix-ui/react-dialog";
import * as Tooltip from "@radix-ui/react-tooltip";
import { AnimatePresence, motion } from "motion/react";
import { AlertCircle, Archive, CheckCircle2, Inbox, LoaderCircle, X } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { describeError } from "../api/client";

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

export function Button({ className = "", variant = "primary", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return <button className={`button button--${variant} ${className}`.trim()} {...props} />;
}

export function IconButton({ label, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string; children: ReactNode }) {
  return (
    <Tooltip.Provider delayDuration={450}>
      <Tooltip.Root>
        <Tooltip.Trigger asChild>
          <button aria-label={label} className="icon-button" {...props}>{children}</button>
        </Tooltip.Trigger>
        <Tooltip.Portal>
          <Tooltip.Content className="tooltip" sideOffset={8}>{label}<Tooltip.Arrow className="tooltip-arrow" /></Tooltip.Content>
        </Tooltip.Portal>
      </Tooltip.Root>
    </Tooltip.Provider>
  );
}

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  wide = false,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <AnimatePresence>
        {open ? (
          <Dialog.Portal forceMount>
            <Dialog.Overlay asChild forceMount>
              <motion.div className="modal-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} />
            </Dialog.Overlay>
            <Dialog.Content asChild forceMount aria-describedby={description ? undefined : undefined}>
              <motion.div
                className={`modal ${wide ? "modal--wide" : ""}`}
                initial={{ opacity: 0, y: 14, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 10, scale: 0.985 }}
                transition={{ duration: 0.18 }}
              >
                <div className="modal__header">
                  <div>
                    <Dialog.Title>{title}</Dialog.Title>
                    {description ? <Dialog.Description>{description}</Dialog.Description> : null}
                  </div>
                  <Dialog.Close asChild><IconButton label="Close dialog"><X size={18} /></IconButton></Dialog.Close>
                </div>
                <div className="modal__body">{children}</div>
                {footer ? <div className="modal__footer">{footer}</div> : null}
              </motion.div>
            </Dialog.Content>
          </Dialog.Portal>
        ) : null}
      </AnimatePresence>
    </Dialog.Root>
  );
}

export function LoadingState({ label = "Opening the vault…", compact = false }: { label?: string; compact?: boolean }) {
  return (
    <div className={`state state--loading ${compact ? "state--compact" : ""}`} role="status">
      <LoaderCircle className="spin" size={compact ? 18 : 24} />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({ error, onRetry, title = "We hit a locked door" }: { error: unknown; onRetry?: () => void; title?: string }) {
  return (
    <div className="state state--error" role="alert">
      <span className="state__icon"><AlertCircle size={22} /></span>
      <div>
        <h3>{title}</h3>
        <p>{describeError(error)}</p>
      </div>
      {onRetry ? <Button variant="secondary" onClick={onRetry}>Try again</Button> : null}
    </div>
  );
}

export function EmptyState({
  icon = "empty",
  title,
  description,
  action,
}: {
  icon?: "empty" | "archive" | "success";
  title: string;
  description: string;
  action?: ReactNode;
}) {
  const Icon = icon === "archive" ? Archive : icon === "success" ? CheckCircle2 : Inbox;
  return (
    <motion.div className="empty-state" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <span className="empty-state__icon"><Icon size={24} strokeWidth={1.7} /></span>
      <h3>{title}</h3>
      <p>{description}</p>
      {action ? <div className="empty-state__action">{action}</div> : null}
    </motion.div>
  );
}

export function Field({ label, hint, error, children }: { label: string; hint?: string | undefined; error?: string | undefined; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field__label">{label}</span>
      {children}
      {error ? <span className="field__error">{error}</span> : hint ? <span className="field__hint">{hint}</span> : null}
    </label>
  );
}

export function StatusPill({ tone = "neutral", children }: { tone?: "neutral" | "success" | "warning" | "danger" | "accent"; children: ReactNode }) {
  return <span className={`status-pill status-pill--${tone}`}>{children}</span>;
}

export function SkeletonRows({ count = 6 }: { count?: number }) {
  return (
    <div aria-label="Loading" className="skeleton-list" role="status">
      {Array.from({ length: count }, (_, index) => (
        <div className="skeleton-row" key={index}>
          <span className="skeleton skeleton--icon" />
          <span className="skeleton skeleton--name" />
          <span className="skeleton skeleton--meta" />
          <span className="skeleton skeleton--short" />
        </div>
      ))}
    </div>
  );
}
