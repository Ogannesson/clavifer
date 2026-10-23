import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api, authFault, emptyStatus, Fault, type Status } from './api';
import { auth, TABS, type AppApi, type Owner, type TabId } from './shell';
import { Icon, Toasts, useConfirm, type Toast } from './ui';
import { ConsentPage, DevicePage, LoginPage, Reauth, Setup } from './entry';
import { Overview } from './pages/overview';
import { Secrets } from './pages/secrets';
import { Connections } from './pages/connections';
import { Clients } from './pages/clients';
import { Access } from './pages/access';
import { Backup } from './pages/backup';
import { Audit } from './pages/audit';
import { Account } from './pages/account';

type PageProps = { app: AppApi };
const PAGES: Record<TabId, (props: PageProps) => ReactNode> = {
  overview: Overview,
  secrets: Secrets,
  connections: Connections,
  clients: Clients,
  access: Access,
  backup: Backup,
  audit: Audit,
  account: Account,
};
const isTab = (value: string | null): value is TabId => !!value && value in PAGES;
const readTab = (): TabId => {
  const value = new URLSearchParams(location.search).get('tab');
  return isTab(value) ? value : 'overview';
};

export function App() {
  const [boot, setBoot] = useState<'loading' | 'ready' | 'failed'>('loading');
  const [initialized, setInitialized] = useState(false);
  const [owner, setOwner] = useState<Owner>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [tab, setTab] = useState<TabId>(readTab);
  const [busy, setBusy] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  // Set while the re-verification dialog is open; called with the Owner's answer.
  const [reauth, setReauth] = useState<((verified: boolean) => void) | null>(null);
  // Calls that fail while the dialog is already open wait for the same answer, then each retries.
  const verifying = useRef<Promise<boolean> | null>(null);
  const current = useRef<HTMLButtonElement>(null);
  const confirm = useConfirm();

  const notify = useCallback((text: string, error = false) => {
    const id = Date.now() + Math.random();
    setToasts((list) => [...list.slice(-2), { id, text, error }]);
    // Every toast disappears on its own and at most three show at once; a failure stays longer to be read.
    setTimeout(() => setToasts((list) => list.filter((t) => t.id !== id)), error ? 8000 : 4500);
  }, []);

  const refresh = useCallback(async () => {
    setInitialized(!!(await api('/healthz')).initialized);
    const session = await auth.getSession();
    const user = session.data?.user as { name: string; email: string } | undefined;
    setOwner(user ? { name: user.name, email: user.email } : null);
    const next = user ? ((await api('/admin/status')) as unknown as Status) : null;
    setStatus(next);
    return next;
  }, []);

  const run = useCallback(
    async (fn: () => Promise<void>, success = '已完成。') => {
      setBusy(true);
      try {
        await fn().catch(async (e: unknown) => {
          // Each of these is cleared by signing in again. The Owner does that in a dialog over the
          // page, which stays mounted with its forms, and the same call then runs once more.
          if (
            !(e instanceof Fault) ||
            !['recent_login_required', 'owner_auth_required', 'UNAUTHORIZED', 'SESSION_NOT_FRESH'].includes(e.code)
          )
            throw e;
          verifying.current ??= new Promise<boolean>((resolve) =>
            setReauth(() => (answer: boolean) => {
              verifying.current = null;
              setReauth(null);
              resolve(answer);
            }),
          );
          const verified = await verifying.current;
          if (!verified) throw new Error('操作未完成，可重新验证后再试。');
          await fn();
        });
        if (success) notify(success);
      } catch (e) {
        notify(e instanceof Error ? e.message : '操作失败。', true);
      } finally {
        setBusy(false);
      }
    },
    [notify],
  );

  const signOut = useCallback(async () => {
    // A sign-out the server refused leaves the session alive, so the page must not pretend otherwise.
    const r = await auth.signOut();
    if (r.error) throw authFault(r.error);
    setStatus(null);
    setOwner(null);
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        await refresh();
        setBoot('ready');
      } catch (e) {
        notify(e instanceof Error ? e.message : '无法连接服务。', true);
        setBoot('failed');
      }
    })();
  }, [refresh, notify]);
  // On a phone the navigation is a horizontal strip, so the active section has to be scrolled to.
  useEffect(() => {
    current.current?.scrollIntoView({ block: 'nearest', inline: 'center' });
  }, [tab]);
  useEffect(() => {
    const onPop = () => setTab(readTab());
    addEventListener('popstate', onPop);
    return () => removeEventListener('popstate', onPop);
  }, []);

  const go = useCallback((next: TabId) => {
    history.pushState({}, '', next === 'overview' ? location.pathname : `${location.pathname}?tab=${next}`);
    setTab(next);
    scrollTo({ top: 0 });
  }, []);

  const app: AppApi = useMemo(
    () => ({
      status: status ?? emptyStatus(),
      loading: status === null,
      busy,
      owner,
      refresh,
      run,
      go,
      notify,
      signOut,
    }),
    [status, busy, owner, refresh, run, go, notify, signOut],
  );

  // Every page renders this outside its own content, so the dialog also serves the entry pages.
  const toastBar = (
    <>
      <Reauth email={owner?.email ?? ''} onDone={reauth} notify={notify} />
      <Toasts items={toasts} onDismiss={(id) => setToasts((list) => list.filter((t) => t.id !== id))} />
    </>
  );

  if (boot === 'loading')
    return (
      <div className="entry">
        <p className="eyebrow">正在连接服务…</p>
      </div>
    );
  if (boot === 'failed')
    return (
      <>
        <div className="entry">
          <div className="entry-card">
            <h1>无法连接服务</h1>
            <p>请确认服务正在运行，然后重试。</p>
            <button
              type="button"
              className="btn btn--block"
              onClick={() => {
                setBoot('loading');
                void (async () => {
                  try {
                    await refresh();
                    setBoot('ready');
                  } catch (e) {
                    notify(e instanceof Error ? e.message : '无法连接服务。', true);
                    setBoot('failed');
                  }
                })();
              }}
            >
              重试
            </button>
          </div>
        </div>
        {toastBar}
      </>
    );
  // An uninitialized instance has nothing but its setup page; an initialized one shows it at /setup,
  // where a recovery token resets the Owner's login.
  if (!initialized || location.pathname === '/setup') return <Setup app={app} toasts={toastBar} />;
  if (location.pathname === '/device') return <DevicePage app={app} toasts={toastBar} />;
  if (location.pathname === '/consent') return <ConsentPage app={app} toasts={toastBar} />;
  // /login only appears with an OAuth query behind it; without one a signed-in Owner belongs in the console.
  if (!owner || (location.pathname === '/login' && location.search)) return <LoginPage app={app} toasts={toastBar} />;

  const Page = PAGES[tab];
  return (
    <>
      <div className="shell">
        <nav className="spine" aria-label="管理导航">
          <div className="brand">
            <span className="brand-mark">
              <Icon name="shield" size={26} />
            </span>
            <span className="brand-name">Clavifer</span>
          </div>
          <div className="nav">
            {TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                className="nav-item"
                ref={t.id === tab ? current : undefined}
                aria-current={t.id === tab ? 'page' : undefined}
                onClick={() => go(t.id)}
              >
                <Icon name={t.icon} size={17} />
                {t.label}
                {t.id === 'access' && app.status.pending.length ? (
                  <span className="nav-count">{app.status.pending.length}</span>
                ) : null}
              </button>
            ))}
            {/* /device is its own entry page because the CLI prints a link to it. */}
            <button type="button" className="nav-item" onClick={() => location.assign('/device')}>
              <Icon name="check" size={17} />
              批准设备
            </button>
          </div>
          <div className="spine-foot">
            <span className="owner">{owner.email}</span>
            <button
              type="button"
              className="btn btn--quiet"
              disabled={busy}
              onClick={() =>
                void (async () => {
                  const ok = await confirm({
                    title: '退出网页登录',
                    body: '已授权的安装实例不受影响，可随时重新登录。',
                    confirmLabel: '退出',
                  });
                  if (ok) await run(signOut, '');
                })()
              }
            >
              <Icon name="logout" size={16} />
              退出网页
            </button>
          </div>
        </nav>
        <main className="main">
          <Page app={app} />
        </main>
      </div>
      {toastBar}
    </>
  );
}
