import { useRef, useState, type FormEvent, type ReactNode } from 'react';
import { api, authFault, fv } from './api';
import { auth, type AppApi } from './shell';
import { Field, Icon, useOverlay } from './ui';

/** Pre-console pages share one centred card: initialization, login, device approval and consent. */
function EntryCard({
  title,
  description,
  children,
  toasts,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  toasts: ReactNode;
}) {
  return (
    <>
      <div className="entry">
        <div className="entry-card">
          <div className="entry-brand">
            <span className="brand-mark">
              <Icon name="shield" size={24} />
            </span>
            <span className="brand-name">Clavifer</span>
          </div>
          <h1>{title}</h1>
          {description ? <p>{description}</p> : null}
          {children}
        </div>
      </div>
      {toasts}
    </>
  );
}

function redirect(raw: string) {
  const target = new URL(raw, location.origin);
  if (
    target.protocol !== 'https:' &&
    !(target.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(target.hostname))
  )
    throw new Error('授权返回地址不受支持。');
  location.assign(target.href);
}

const submit = (app: AppApi, handler: (f: FormData) => Promise<void>, success?: string) => (e: FormEvent) => {
  e.preventDefault();
  const form = e.currentTarget as HTMLFormElement;
  void app.run(() => handler(new FormData(form)), success);
};

export function Bootstrap({ app, toasts }: { app: AppApi; toasts: ReactNode }) {
  return (
    <EntryCard
      title="创建管理员"
      description="本服务只有一个管理员。请在本机打开初始化文件读取令牌，不要把它粘贴到 Agent 对话或日志中。"
      toasts={toasts}
    >
      <form
        onSubmit={submit(
          app,
          async (f) => {
            const email = fv(f, 'email');
            const password = fv(f, 'password');
            await api(
              '/bootstrap',
              'POST',
              { name: fv(f, 'name'), email, password },
              { 'x-bootstrap-token': fv(f, 'token') },
            );
            const r = await auth.signIn.email({ email, password });
            if (r.error) throw authFault(r.error);
            await app.refresh();
          },
          '管理员已创建，已为你登录。',
        )}
      >
        <Field label="初始化令牌" hint="位于本机 work/local-bootstrap.token 或部署时保存的位置。">
          <input name="token" type="password" autoComplete="off" required />
        </Field>
        <Field label="姓名">
          <input name="name" autoComplete="name" required />
        </Field>
        <Field label="邮箱">
          <input name="email" type="email" autoComplete="username" required />
        </Field>
        <Field label="新密码" hint="至少 12 位。没有邮件找回，请存入你自己的密码管理器。">
          <input name="password" type="password" autoComplete="new-password" minLength={12} required />
        </Field>
        <button className="btn btn--block" disabled={app.busy}>
          创建管理员
        </button>
      </form>
    </EntryCard>
  );
}

export function LoginPage({ app, toasts, note }: { app: AppApi; toasts: ReactNode; note?: string }) {
  const oauth = location.pathname === '/login' && location.search;
  const afterLogin = async () => {
    await app.refresh();
    if (oauth) {
      const r = await api('/api/auth/oauth2/continue', 'POST', {
        oauth_query: location.search.slice(1),
        selected: true,
      });
      redirect(String(r.url));
    }
  };
  if (oauth && app.owner)
    return (
      <EntryCard
        title="正在返回客户端"
        description="已登录。把授权结果交回客户端需要 10 分钟内的登录，登录较早时会先请你重新验证。"
        toasts={toasts}
      >
        <button className="btn btn--block" disabled={app.busy} onClick={() => void app.run(afterLogin, '')}>
          继续
        </button>
      </EntryCard>
    );
  return (
    <EntryCard
      title="管理员登录"
      description={note ?? '日常优先使用 Passkey。密码仅作为恢复与兼容入口。'}
      toasts={toasts}
    >
      <form
        onSubmit={submit(
          app,
          async (f) => {
            const r = await auth.signIn.email({ email: fv(f, 'email'), password: fv(f, 'password') });
            if (r.error) throw authFault(r.error);
            await afterLogin();
          },
          '已登录。',
        )}
      >
        <Field label="邮箱">
          <input name="email" type="email" autoComplete="username" required />
        </Field>
        <Field label="密码">
          <input name="password" type="password" autoComplete="current-password" required />
        </Field>
        <button className="btn btn--block" disabled={app.busy}>
          使用密码登录
        </button>
      </form>
      <div className="entry-alt">
        <button
          type="button"
          className="btn btn--ghost btn--block"
          disabled={app.busy}
          onClick={() =>
            void app.run(async () => {
              const r = await auth.signIn.passkey();
              if (r?.error) throw authFault(r.error);
              await afterLogin();
            }, '已使用 Passkey 登录。')
          }
        >
          <Icon name="shield" size={16} />
          使用 Passkey 登录
        </button>
      </div>
    </EntryCard>
  );
}

/**
 * Opened by app.run when the server wants a fresh login. Signing in again issues a new session in
 * place, so the page and any half-filled form underneath stay mounted while the Owner verifies.
 */
export function Reauth({
  email,
  onDone,
  notify,
}: {
  email: string;
  onDone: ((verified: boolean) => void) | null;
  notify: (text: string, error?: boolean) => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [pending, setPending] = useState(false);
  useOverlay(!!onDone, () => onDone?.(false), ref);
  const verify = async (signIn: () => Promise<void>) => {
    setPending(true);
    try {
      await signIn();
      onDone?.(true);
    } catch (e) {
      notify(e instanceof Error ? e.message : '验证失败。', true);
    } finally {
      setPending(false);
    }
  };
  // Like a drawer, the scrim only blocks: a stray click must not cancel the verification.
  return (
    <>
      {onDone ? <div className="scrim scrim--top" /> : null}
      <dialog className="confirm" ref={ref} aria-label="重新验证身份">
        {onDone ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const f = new FormData(e.currentTarget);
              void verify(async () => {
                const r = await auth.signIn.email({ email: fv(f, 'email'), password: fv(f, 'password') });
                if (r.error) throw authFault(r.error);
              });
            }}
          >
            <div className="confirm-body">
              <h2>重新验证身份</h2>
              <p>登录已过期，或这项操作需要 10 分钟内的登录。验证后会自动重试刚才的操作，页面上填写的内容会保留。</p>
              <button
                type="button"
                className="btn btn--block"
                disabled={pending}
                onClick={() =>
                  void verify(async () => {
                    const r = await auth.signIn.passkey();
                    if (r?.error) throw authFault(r.error);
                  })
                }
              >
                <Icon name="shield" size={16} />
                使用 Passkey 验证
              </button>
              <div className="entry-alt">
                <Field label="邮箱">
                  <input name="email" type="email" autoComplete="username" required defaultValue={email} />
                </Field>
                <Field label="密码">
                  <input name="password" type="password" autoComplete="current-password" required />
                </Field>
              </div>
            </div>
            <div className="confirm-actions">
              <button type="button" className="btn btn--quiet" disabled={pending} onClick={() => onDone(false)}>
                取消
              </button>
              <button className="btn btn--ghost" disabled={pending}>
                使用密码验证
              </button>
            </div>
          </form>
        ) : null}
      </dialog>
    </>
  );
}

type Review = { code: string; clientId: string; scope: string; grants: number };
export function DevicePage({ app, toasts }: { app: AppApi; toasts: ReactNode }) {
  const [review, setReview] = useState<Review | null>(null);
  const [done, setDone] = useState('');
  if (!app.owner) return <LoginPage app={app} toasts={toasts} note="登录管理员后即可查看并批准设备短码。" />;
  const clientName = (id: string) => app.status.clients.find((c) => c.clientId === id)?.name ?? id;
  // The short-code field is prefilled from user_code, so a code left behind must leave the URL too.
  const another = () => {
    history.replaceState(null, '', location.pathname);
    setReview(null);
    setDone('');
  };
  if (done)
    return (
      <EntryCard title="设备请求已处理" description={done} toasts={toasts}>
        <div className="form-actions">
          <button type="button" className="btn" onClick={another}>
            处理另一个设备
          </button>
          <button type="button" className="btn btn--ghost" onClick={() => location.assign('/')}>
            回到管理控制台
          </button>
        </div>
      </EntryCard>
    );
  return (
    <EntryCard
      title="批准设备登录"
      description="只批准你刚刚发起、且短码一致的请求。授权按安装实例保存：批准后，这台设备立即拥有该实例现有的全部授权。"
      toasts={toasts}
    >
      {review ? (
        <>
          <div className="review">
            <dl>
              <dt>安装实例</dt>
              <dd>{clientName(review.clientId)}</dd>
              <dt>设备短码</dt>
              <dd className="mono">{review.code}</dd>
              <dt>请求的登录权限</dt>
              <dd className="mono">{review.scope}</dd>
              <dt>该实例现有授权</dt>
              <dd>
                {review.grants
                  ? `${review.grants} 条有效授权，批准后这台设备立即可用`
                  : '暂无；之后授予该实例的授权，这台设备同样获得'}
              </dd>
            </dl>
          </div>
          <div className="form-actions">
            {(['approve', 'deny'] as const).map((decision) => (
              <button
                key={decision}
                type="button"
                className={decision === 'approve' ? 'btn' : 'btn btn--ghost'}
                disabled={app.busy}
                onClick={() =>
                  void app.run(async () => {
                    await api('/api/auth/device/' + decision, 'POST', { userCode: review.code });
                    setDone(decision === 'approve' ? '可以回到电脑继续登录。' : '该设备请求已被拒绝。');
                  }, '')
                }
              >
                {decision === 'approve' ? '批准此设备' : '拒绝'}
              </button>
            ))}
            <button type="button" className="btn btn--quiet" onClick={another}>
              换一个短码
            </button>
          </div>
        </>
      ) : (
        <form
          onSubmit={submit(
            app,
            async (f) => {
              const code = fv(f, 'userCode').trim();
              const r = await api('/api/auth/device?user_code=' + encodeURIComponent(code));
              const clientId = String(r.client_id ?? '');
              // Counted from the grants the server lists as valid at this moment, not from what the
              // page loaded earlier.
              const grants = (await app.refresh())?.grants.filter((g) => g.client_id === clientId).length ?? 0;
              setReview({ code, clientId, scope: String(r.scope ?? ''), grants });
            },
            '',
          )}
        >
          <Field label="设备短码" hint="来自客户端终端的提示，区分大小写。">
            <input
              name="userCode"
              autoComplete="off"
              required
              defaultValue={new URLSearchParams(location.search).get('user_code') ?? ''}
            />
          </Field>
          <button className="btn btn--block" disabled={app.busy}>
            查看请求
          </button>
          <div className="entry-alt">
            <button type="button" className="btn btn--ghost btn--block" onClick={() => location.assign('/')}>
              回到管理控制台
            </button>
          </div>
        </form>
      )}
    </EntryCard>
  );
}

export function ConsentPage({ app, toasts }: { app: AppApi; toasts: ReactNode }) {
  if (!app.owner) return <LoginPage app={app} toasts={toasts} note="登录管理员后即可确认客户端的登录请求。" />;
  const query = new URLSearchParams(location.search);
  // The authorization redirect signs its query; opened by hand, there is no request to decide on.
  const pending = query.has('sig');
  const decide = (accept: boolean) =>
    void app.run(async () => {
      const r = await api('/api/auth/oauth2/consent', 'POST', { accept, oauth_query: location.search.slice(1) });
      redirect(String(r.url));
    }, '');
  return (
    <EntryCard
      title="确认客户端登录权限"
      description={
        pending
          ? '授权按安装实例保存：同意后，这个客户端立即拥有其实例现有的全部授权；其余凭据与连接仍需在“授权”中授予。'
          : '这个链接缺少客户端的登录请求参数。请回到客户端重新发起登录，并从它打开的页面完成确认。'
      }
      toasts={toasts}
    >
      <div className="review">
        <dl>
          <dt>客户端</dt>
          <dd className="mono">{query.get('client_id') ?? '—'}</dd>
          <dt>请求权限</dt>
          <dd className="mono">{query.get('scope') ?? '—'}</dd>
        </dl>
      </div>
      <div className="form-actions">
        <button type="button" className="btn" disabled={app.busy || !pending} onClick={() => decide(true)}>
          同意登录
        </button>
        <button type="button" className="btn btn--ghost" disabled={app.busy || !pending} onClick={() => decide(false)}>
          拒绝
        </button>
      </div>
    </EntryCard>
  );
}
