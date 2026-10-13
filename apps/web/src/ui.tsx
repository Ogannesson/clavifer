import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from 'react';
import { createPortal } from 'react-dom';

/** Inline SVG keeps the icon set inside the bundle; no icon package and no remote requests. */
const paths: Record<string, ReactNode> = {
  shield: <path d="M12 3 4.5 6v5.6c0 4.3 3.1 7.7 7.5 9.4 4.4-1.7 7.5-5.1 7.5-9.4V6Z" />,
  gauge: (
    <>
      <path d="M4 17a8 8 0 1 1 16 0" />
      <path d="m12 17 4-5" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="12" r="3.4" />
      <path d="M11.4 12H20m-3 0v3m-2.6-3v2.2" />
    </>
  ),
  link: (
    <>
      <path d="M10.5 13.5a3.5 3.5 0 0 0 5 0l2.5-2.5a3.5 3.5 0 0 0-5-5l-1 1" />
      <path d="M13.5 10.5a3.5 3.5 0 0 0-5 0L6 13a3.5 3.5 0 0 0 5 5l1-1" />
    </>
  ),
  device: (
    <>
      <rect x="3" y="5" width="18" height="12" rx="1.6" />
      <path d="M8 20h8" />
    </>
  ),
  grant: (
    <>
      <path d="M12 3 5 6v5.5c0 4 2.9 7.3 7 8.9 4.1-1.6 7-4.9 7-8.9V6Z" />
      <path d="m9.2 12 2 2 3.6-3.8" />
    </>
  ),
  archive: (
    <>
      <rect x="3.5" y="5" width="17" height="4" rx="1" />
      <path d="M5.5 9v9.5h13V9M10 13h4" />
    </>
  ),
  ledger: (
    <>
      <path d="M5.5 4h13v16h-13z" />
      <path d="M9 8.5h6M9 12h6M9 15.5h4" />
    </>
  ),
  user: (
    <>
      <circle cx="12" cy="8.5" r="3.5" />
      <path d="M5.5 20c.6-3.5 3.2-5.5 6.5-5.5s5.9 2 6.5 5.5" />
    </>
  ),
  alert: (
    <>
      <path d="M12 4.5 3 19.5h18Z" />
      <path d="M12 10v4m0 2.5v.6" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5.5m0-8.6v.6" />
    </>
  ),
  check: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="m8.3 12.2 2.6 2.6 4.8-5.2" />
    </>
  ),
  close: <path d="m6.5 6.5 11 11m0-11-11 11" />,
  plus: <path d="M12 5.5v13M5.5 12h13" />,
  refresh: (
    <>
      <path d="M19 12a7 7 0 1 1-2.2-5.1" />
      <path d="M19.5 4v3.6H16" />
    </>
  ),
  logout: (
    <>
      <path d="M14 6.5V4.5H5v15h9v-2" />
      <path d="M11 12h9m-3-3 3 3-3 3" />
    </>
  ),
  download: (
    <>
      <path d="M12 4v10m-3.5-3.5L12 14l3.5-3.5" />
      <path d="M5 17.5v2h14v-2" />
    </>
  ),
};
export function Icon({ name, size = 18 }: { name: keyof typeof paths | string; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {paths[name]}
    </svg>
  );
}

export type Tone = 'neutral' | 'ok' | 'warn' | 'danger' | 'accent';
export const Badge = ({ tone = 'neutral', children }: { tone?: Tone; children: ReactNode }) => (
  <span className={tone === 'neutral' ? 'badge' : `badge badge--${tone}`}>{children}</span>
);

export function Panel({
  title,
  description,
  actions,
  children,
}: {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      {title ? (
        <div className="panel-head">
          <div>
            <h2>{title}</h2>
            {description ? <p>{description}</p> : null}
          </div>
          {actions ? <div className="page-actions">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}

export const EmptyState = ({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) => (
  <div className="empty">
    <h3>{title}</h3>
    {description ? <p>{description}</p> : null}
    {action}
  </div>
);

export const Loading = ({ label = '加载中…' }: { label?: string }) => (
  <div className="loading" role="status" aria-live="polite">
    <span className="eyebrow">{label}</span>
    <span className="skeleton skeleton--wide" />
    <span className="skeleton" />
    <span className="skeleton skeleton--half" />
  </div>
);

export const Field = ({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) => (
  <label className="field">
    <span>{label}</span>
    {children}
    {hint ? <span className="field-hint">{hint}</span> : null}
  </label>
);

/**
 * Overlays use show() rather than showModal(): a modal dialog makes the rest of the document inert,
 * which would put the toast layer — including the sign-in errors shown while re-verifying on top of
 * an open form — behind the backdrop. The page content is made inert explicitly instead, so the
 * toasts stay reachable, and Escape is handled here because a non-modal dialog ignores it. Only the
 * topmost overlay answers Escape, so dismissing a dialog never also closes the drawer beneath it.
 */
const overlays: object[] = [];
export function useOverlay(open: boolean, onClose: () => void, ref: RefObject<HTMLDialogElement | null>) {
  // inert is inherited by every descendant, so an overlay must live outside the element it silences.
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (!open) {
      if (el.open) el.close();
      return;
    }
    el.show();
    el.querySelector<HTMLElement>('input, select, textarea, button')?.focus();
    const page = document.querySelector('.shell, .entry');
    const token = {};
    if (overlays.push(token) === 1) page?.toggleAttribute('inert', true);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && overlays.at(-1) === token) close.current();
    };
    addEventListener('keydown', onKey);
    return () => {
      removeEventListener('keydown', onKey);
      overlays.splice(overlays.indexOf(token), 1);
      if (!overlays.length) page?.removeAttribute('inert');
    };
    // Only opening focuses the form: re-running on a new onClose identity would steal focus on
    // every re-render, and a re-render happens whenever a field inside the drawer changes.
  }, [open, ref]);
}

export function Drawer({
  open,
  title,
  description,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useOverlay(open, onClose, ref);
  // The page is what goes inert, so the drawer is rendered outside it rather than inside its page.
  // The scrim only blocks and dims; a stray click on it must not discard a half-filled form.
  return createPortal(
    <>
      {open ? <div className="scrim" /> : null}
      <dialog className="drawer" ref={ref} aria-label={title}>
        {open ? (
          <div className="drawer-inner">
            <div className="drawer-head">
              <div>
                <h2>{title}</h2>
                {description ? <p>{description}</p> : null}
              </div>
              <button type="button" className="icon-btn" onClick={onClose} aria-label="关闭">
                <Icon name="close" size={20} />
              </button>
            </div>
            <div className="drawer-body">{children}</div>
          </div>
        ) : null}
      </dialog>
    </>,
    document.body,
  );
}

export type ConfirmRequest = { title: string; body: string; confirmLabel: string; danger?: boolean };
const ConfirmContext = createContext<(request: ConfirmRequest) => Promise<boolean>>(async () => false);
export const useConfirm = () => useContext(ConfirmContext);

/** One dialog serves every destructive action, so each confirmation can spell out its own consequence. */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<ConfirmRequest | null>(null);
  const answer = useRef<(value: boolean) => void>(() => {});
  const ref = useRef<HTMLDialogElement>(null);
  const settle = useCallback((value: boolean) => {
    answer.current(value);
    setRequest(null);
  }, []);
  const cancel = useCallback(() => settle(false), [settle]);
  useOverlay(!!request, cancel, ref);
  // A destructive confirmation starts on 取消, so a reflexive Enter cannot carry it out.
  useEffect(() => {
    if (request) ref.current?.querySelectorAll('button')[request.danger ? 0 : 1]?.focus();
  }, [request]);
  return (
    <ConfirmContext
      value={(next) =>
        new Promise<boolean>((resolve) => {
          answer.current = resolve;
          setRequest(next);
        })
      }
    >
      {children}
      {request ? <div className="scrim scrim--top" onClick={cancel} /> : null}
      <dialog className="confirm" ref={ref} aria-label={request?.title ?? '确认'}>
        {request ? (
          <>
            <div className="confirm-body">
              <h2>{request.title}</h2>
              <p>{request.body}</p>
            </div>
            <div className="confirm-actions">
              <button type="button" className="btn btn--ghost" onClick={cancel}>
                取消
              </button>
              <button type="button" className={request.danger ? 'btn btn--danger' : 'btn'} onClick={() => settle(true)}>
                {request.confirmLabel}
              </button>
            </div>
          </>
        ) : null}
      </dialog>
    </ConfirmContext>
  );
}

export type Toast = { id: number; text: string; error?: boolean };
export function Toasts({ items, onDismiss }: { items: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div className="toasts" role="status" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className={t.error ? 'toast toast--error' : 'toast'}>
          <span className="alert-icon">
            <Icon name={t.error ? 'alert' : 'check'} size={17} />
          </span>
          <p>{t.text}</p>
          <button type="button" className="icon-btn toast-close" onClick={() => onDismiss(t.id)} aria-label="关闭提示">
            <Icon name="close" size={16} />
          </button>
        </div>
      ))}
    </div>
  );
}
