import { Fragment, useState, type ReactNode } from 'react';
import {
  api,
  clientName,
  Fault,
  fieldText,
  fv,
  hostedSuffixText,
  lines,
  METHODS,
  parseAuth,
  parsePolicy,
  parseRequested,
  relativeText,
  resourceName,
  ruleKindText,
  timeText,
  type DraftAuth,
  type Grant,
  type Invocation,
  type Pending,
  type PolicyTest,
  type RequestedGrant,
  type Setup,
  type Update,
} from '../api';
import { PageHead, RefreshButton, type AppApi } from '../shell';
import { Badge, Drawer, EmptyState, Field, Icon, Loading, Panel, useConfirm } from '../ui';

/** A grant inside this window is close enough to expiry that the Owner may need to renew it. */
export const EXPIRING_SOON = 2 * 3600 * 1000;
export const isExpiringSoon = (g: Grant) => !!g.expires_at && g.expires_at - Date.now() < EXPIRING_SOON;
const permissionText = (g: { resource_type: string; fields?: string[] | null }) =>
  g.resource_type === 'secret' ? `读取凭据 · ${fieldText(g.fields)}` : '通过 API 连接调用';
/** Expiry choices in milliseconds, shared by a direct grant and an approval; 0 means until revoked. */
const DURATIONS = [
  ['3600000', '1 小时'],
  ['86400000', '24 小时'],
  ['2592000000', '30 天'],
  ['0', '直到手动撤销'],
] as const;
const durationOptions = DURATIONS.map(([value, label]) => (
  <option key={value} value={value}>
    {label}
  </option>
));
const expiresAtFor = (duration: string) => (Number(duration) ? Date.now() + Number(duration) : null);

/** Shown both on the overview and on this page: the same decision, wherever the Owner sees it. */
export function PendingCard({ app, request }: { app: AppApi; request: Pending }) {
  const requested = parseRequested(request);
  return requested.setup ? (
    <SetupCard app={app} request={request} setup={requested.setup} />
  ) : requested.update ? (
    <UpdateCard
      app={app}
      request={request}
      update={requested.update}
      current={requested.current}
      updatedAt={requested.updatedAt}
    />
  ) : requested.invocation ? (
    <InvocationCard app={app} request={request} invocation={requested.invocation} />
  ) : (
    <GrantRequestCard app={app} request={request} grants={requested.grants} />
  );
}

function useDeny(app: AppApi, request: Pending, consequence: string) {
  const confirm = useConfirm();
  return async () => {
    const ok = await confirm({
      title: '拒绝这条申请',
      body: `${consequence}申请随即消失。Agent 需要重新提交才能再次请求。`,
      confirmLabel: '拒绝申请',
      danger: true,
    });
    if (!ok) return;
    await app.run(async () => {
      await api(`/admin/access-requests/${request.id}/deny`, 'POST');
      await app.refresh();
    }, '已拒绝该申请。');
  };
}

/** The reason comes first and largest: it names the target and effect the Owner checks the request against.
 * Only lead, which the server derives from the request itself, may stand above it, so nothing the Agent
 * wrote can be read before it. */
function PendingShell({
  title,
  request,
  lead,
  children,
}: {
  title: string;
  request: Pending;
  lead?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="alert alert--warn">
      <span className="alert-icon">
        <Icon name="alert" size={18} />
      </span>
      <div className="alert-body">
        <span className="small muted">{title}</span>
        {lead}
        <p className="request-reason">{request.reason || '申请没有填写理由。'}</p>
        {children}
      </div>
    </div>
  );
}

const connectionScope = (app: AppApi, id: string) => {
  const connection = app.status.connections.find((c) => c.id === id);
  const policy = connection ? parsePolicy(connection) : null;
  return { paths: policy?.paths ?? [], methods: policy?.methods ?? ['GET', 'HEAD'] };
};
const decodedPath = (raw: string) => {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
};
/** An extension the way the server matches it: each path decoded, characters outside printable ASCII
 * escaped, and the path as written beside it when the two differ. */
function ExtensionScope({ paths, methods }: { paths: string[]; methods: string[] }) {
  return (
    <span className="mono">
      {methods.join(' ')} ·{' '}
      {paths.map((raw, i) => {
        const decoded = decodedPath(raw);
        return (
          <span key={i}>
            {i ? '、' : ''}
            <Visible text={decoded} />
            {decoded === raw ? null : (
              <>
                （原文 <Visible text={raw} />）
              </>
            )}
          </span>
        );
      })}
    </span>
  );
}

function GrantRequestCard({ app, request, grants }: { app: AppApi; request: Pending; grants: RequestedGrant[] }) {
  const [duration, setDuration] = useState('3600000');
  const deny = useDeny(app, request, `${clientName(app.status, request.client_id)} 不会获得这些资源，`);
  const approve = () =>
    app.run(async () => {
      const until = expiresAtFor(duration);
      try {
        await api(`/admin/access-requests/${request.id}/approve`, 'POST', { expiresAt: until });
      } catch (e) {
        // The Owner resolves a field-range conflict by hand, so send them straight to the grant list.
        if (e instanceof Fault && e.code === 'existing_grant_conflict') app.go('access');
        throw e;
      }
      // A live grant keeps a later expiry than the one chosen here, so report what the server kept.
      const next = await app.refresh();
      const kept = new Set(
        grants.map(
          (g) =>
            next?.grants.find(
              (x) =>
                x.client_id === request.client_id && x.resource_id === g.resourceId && x.permission === g.permission,
            )?.expires_at,
        ),
      );
      const [only] = kept;
      // An extension keeps the expiry chosen here even when the grant already lasts longer.
      const extension = !grants.some((g) => g.paths || g.methods)
        ? ''
        : until === null
          ? '临时扩展范围直到授权撤销。'
          : `临时扩展范围到 ${timeText(until)}（${relativeText(until)}）。`;
      app.notify(
        (kept.size !== 1 || only === undefined
          ? '已批准，各资源的到期时间见授权列表。'
          : only === null
            ? '已批准，授权直到手动撤销。'
            : `已批准，授权到 ${timeText(only)}（${relativeText(only)}）。`) + extension,
      );
    }, '');
  return (
    <PendingShell title={`${clientName(app.status, request.client_id)} 申请资源权限`} request={request}>
      <ul className="request-grants">
        {grants.map((g, i) => (
          <li key={i}>
            {resourceName(app.status, g.resourceId)} · {g.permission}
            {g.permission === 'secret:read' ? ` · ${fieldText(g.fields)}` : ''}
            {g.paths || g.methods ? (
              <p className="request-extension">
                <Badge tone="warn">临时扩展范围</Badge> 超出连接允许的路径和方法：
                {/* A list the Agent left out is fixed to the connection's current one on approval. */}
                <ExtensionScope
                  paths={g.paths ?? connectionScope(app, g.resourceId).paths}
                  methods={g.methods ?? connectionScope(app, g.resourceId).methods}
                />
              </p>
            ) : null}
          </li>
        ))}
      </ul>
      <p className="small muted">申请将在 {relativeText(request.expires_at)}失效。</p>
      <div className="alert-actions">
        <select aria-label="授权有效期" value={duration} onChange={(e) => setDuration(e.target.value)}>
          {durationOptions}
        </select>
        <button type="button" className="btn btn--small" disabled={app.busy} onClick={() => void approve()}>
          批准
        </button>
        <button type="button" className="btn btn--ghost btn--small" disabled={app.busy} onClick={() => void deny()}>
          拒绝
        </button>
      </div>
    </PendingShell>
  );
}

/** An indented copy of a JSON body, only as a reading aid: parsing drops duplicate keys and rounds
 * large numbers, so the raw body stays the authoritative view. Null when it adds nothing. */
const formattedBody = (body: string | undefined) => {
  try {
    const text = JSON.stringify(JSON.parse(body ?? ''), null, 2);
    return text === body ? null : text;
  } catch {
    return null;
  }
};
const escape = (cp: number) =>
  cp > 0xffff ? `\\u{${cp.toString(16).toUpperCase()}}` : '\\u' + cp.toString(16).toUpperCase().padStart(4, '0');
/** Shows text as sent, except that every character outside printable ASCII (control and format
 * characters such as bidi overrides and zero-width marks, and any non-ASCII letter) becomes a marked
 * \uXXXX escape, so the review cannot read differently from what runs. lines keeps line breaks. */
function Visible({ text, lines = false }: { text: string; lines?: boolean }) {
  const parts: ReactNode[] = [];
  let plain = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if ((cp >= 0x20 && cp <= 0x7e) || (lines && ch === '\n')) {
      plain += ch;
      continue;
    }
    if (plain) parts.push(plain);
    plain = '';
    parts.push(
      <span className="escaped" key={parts.length}>
        {escape(cp)}
      </span>,
    );
  }
  if (plain) parts.push(plain);
  return <>{parts}</>;
}

/** Which credential fields go to an origin, and how, built from a connection's auth fields and never
 * from anything an Agent wrote. */
function deliverySentence(auth: DraftAuth, url: string) {
  const origin = <code>{url}</code>;
  switch (auth.type) {
    case 'bearer':
      return (
        <>
          凭据字段 <code>{auth.field}</code> 将以 Bearer 方式发往 {origin}
        </>
      );
    case 'header':
      return (
        <>
          凭据字段 <code>{auth.field}</code> 将作为请求头 <code>{auth.name}</code> 发往 {origin}
        </>
      );
    case 'basic':
      return (
        <>
          凭据字段 <code>{auth.usernameField}</code>（用户名）和 <code>{auth.passwordField}</code>（密码）将以 Basic
          方式发往 {origin}
        </>
      );
    case 'query':
      return (
        <>
          凭据字段 <code>{auth.field}</code> 将作为 URL 参数 <code>{auth.name}</code> 发往 {origin}
        </>
      );
    case 'none':
      return <>这条连接不注入凭据，请求发往 {origin}</>;
  }
}

function InvocationCard({ app, request, invocation }: { app: AppApi; request: Pending; invocation: Invocation }) {
  const [confirmed, setConfirmed] = useState(false);
  const deny = useDeny(app, request, '这次请求不会执行，');
  const connection = app.status.connections.find((c) => c.id === invocation.connection);
  const query = Object.entries(invocation.query ?? {});
  const headers = Object.entries(invocation.headers ?? {});
  const formatted = formattedBody(invocation.body);
  // An approval of a request to another origin names that origin back, as this page showed it: the
  // server refuses one that names none, so an approval only comes from a page that showed the origin.
  const approve = () =>
    app.run(async () => {
      await api(
        `/admin/access-requests/${request.id}/approve`,
        'POST',
        invocation.origin ? { origin: invocation.origin } : undefined,
      );
      await app.refresh();
    }, '已批准这一次请求：Agent 需在 10 分钟内原样执行，只能执行一次。');
  // A request to another origin than the connection's own says so above the reason, from the stored
  // origin, the connection as saved and the server's reading of its extra hosts. An origin that only
  // anyHost covers is one the Owner never listed, so approving it takes a confirmation naming the
  // host; one that nothing covers any more cannot run at all.
  const { elsewhere } = request;
  const auth = connection ? parseAuth(connection) : null;
  const fixed = connection ? (
    <>
      这不是连接「{connection.name}」的固定地址 <code>{connection.origin}</code>
    </>
  ) : null;
  const lead =
    !elsewhere || !invocation.origin ? null : elsewhere.host ? (
      <div className="request-delivery">
        <span className="request-delivery-source">取自申请的目标地址和这条连接当前的设置，不是 Agent 写的文字</span>
        {auth ? <span>{deliverySentence(auth, invocation.origin)}</span> : null}
        <span>
          {fixed}，在该连接的额外域名 <code>{elsewhere.host}</code> 范围内
        </span>
      </div>
    ) : (
      <div className="request-delivery request-delivery--danger">
        <span className="request-delivery-source">取自申请的目标地址和这条连接当前的设置，不是 Agent 写的文字</span>
        {elsewhere.anyHost && auth ? (
          <>
            <span>
              这个地址不在你登记的任何范围内，
              {auth.type === 'none'
                ? '这条连接不注入凭据，批准只是让请求发往该地址'
                : '批准就是把这份凭据交给该地址的运营者'}
            </span>
            <span>{deliverySentence(auth, invocation.origin)}</span>
            <span>{fixed}，只因连接开启了「允许经单次审批发往任意地址」才能申请</span>
            <label className="check">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
              <span>
                我确认{auth.type === 'none' ? '请求' : '凭据'}将发往 <code>{elsewhere.hostname}</code>
              </span>
            </label>
          </>
        ) : (
          <span>
            目标地址 <code>{invocation.origin}</code>{' '}
            已不在这条连接登记的范围内（申请提交后连接被改过或已删除），批准了也不会执行，只能拒绝
          </span>
        )}
      </div>
    );
  const blocked = !!elsewhere && !elsewhere.host && !(elsewhere.anyHost && confirmed);
  return (
    <PendingShell title={`${clientName(app.status, request.client_id)} 申请执行一次请求`} request={request} lead={lead}>
      <dl className="request-call">
        <dt>连接</dt>
        <dd>{connection?.name ?? invocation.connection}</dd>
        <dt>请求</dt>
        <dd>
          <pre>
            {`${invocation.method} ${invocation.origin ?? connection?.origin ?? ''}`}
            <Visible
              text={invocation.path + (query.length ? '?' + query.map(([k, v]) => `${k}=${v}`).join('&') : '')}
            />
          </pre>
        </dd>
        {query.length ? (
          <>
            <dt>查询参数</dt>
            <dd>
              <pre>
                <Visible text={query.map(([k, v]) => `${k} = ${v}`).join('\n')} lines />
              </pre>
            </dd>
          </>
        ) : null}
        <dt>请求头</dt>
        <dd>
          {headers.length ? (
            <pre>
              <Visible text={headers.map(([k, v]) => `${k}: ${v}`).join('\n')} lines />
            </pre>
          ) : (
            '无'
          )}
        </dd>
        <dt>请求体</dt>
        <dd>
          {invocation.body ? (
            <pre>
              <Visible text={invocation.body} lines />
            </pre>
          ) : (
            '无'
          )}
        </dd>
        {formatted ? (
          <>
            <dt>格式化</dt>
            <dd>
              <p className="small muted">仅辅助阅读：重复的键只显示最后一个，过大的数字可能失真，以上方原文为准。</p>
              <pre>
                <Visible text={formatted} lines />
              </pre>
            </dd>
          </>
        ) : null}
      </dl>
      <p className="small muted">
        批准后 10 分钟内有效，只能执行一次，凭据由服务端注入。申请将在 {relativeText(request.expires_at)}失效。
      </p>
      <div className="alert-actions">
        <button type="button" className="btn btn--small" disabled={app.busy || blocked} onClick={() => void approve()}>
          批准这一次请求
        </button>
        <button type="button" className="btn btn--ghost btn--small" disabled={app.busy} onClick={() => void deny()}>
          拒绝
        </button>
      </div>
    </PendingShell>
  );
}

/** A test's decision the way the Owner reads it. */
const verdictText: Record<string, string> = {
  run: '执行',
  path_denied: '拒绝规则禁止',
  approval_required: '需单次审批',
  path_not_allowed: '路径在范围外',
  method_not_allowed: '方法在范围外',
  grant_required: '需要授权',
};
/** The Agent's tests of a draft. Every one matched the draft policy on submission, so its expectation is
 * the result; for an update, current is what the connection decides today. */
function TestTable({ tests, current }: { tests: PolicyTest[]; current?: string[] }) {
  return (
    <div className="table-scroll">
      <table className="request-tests">
        <thead>
          <tr>
            <th>请求</th>
            <th>授权</th>
            {current ? <th>当前</th> : null}
            <th>{current ? '修改后' : '结果'}</th>
          </tr>
        </thead>
        <tbody>
          {tests.map((t, i) => (
            <tr key={i} className={current && current[i] !== t.expect ? 'changed' : undefined}>
              <td className="wrap mono">
                {t.method} <Visible text={t.path} />
              </td>
              <td>{t.grant ? '有时长授权' : '无授权'}</td>
              {current ? <td>{verdictText[current[i]]}</td> : null}
              <td>{verdictText[t.expect]}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
const Lines = ({ items }: { items: string[] }) =>
  items.length ? (
    <pre>
      <Visible text={items.join('\n')} lines />
    </pre>
  ) : (
    <>无</>
  );
/** The sentences a setup is checked against, one for each connection: which credential fields go to
 * which origin, and how. They are built from the draft's origin and auth fields and stand above the
 * reason in a framed block with code-set names, so nothing the Agent wrote can be read first or pass
 * for them. A connection that lists extra hosts adds where else its credential may go, one approved
 * request at a time. */
function Delivery({ setup: { connections } }: { setup: Setup }) {
  return (
    <div className="request-delivery">
      <span className="request-delivery-source">取自草案的服务地址和注入方式字段，不是 Agent 写的文字</span>
      {connections.map((c, i) => (
        <span key={i}>
          {deliverySentence(c.auth, c.origin)}
          {c.hosts?.length ? (
            <>
              ；经你逐次批准后，还可发往这些范围内的地址：
              {c.hosts.map((host, j) => (
                <Fragment key={j}>
                  {j ? '、' : ''}
                  <code>{host}</code>
                </Fragment>
              ))}
            </>
          ) : null}
        </span>
      ))}
      {connections.some((c) => c.hosts?.length) ? <span>{hostedSuffixText}</span> : null}
    </div>
  );
}
/** Free rules run without any grant, for every installation; a card says so wherever approval sets them. */
const freeText = '命中免审批规则的请求，任何安装实例不需授权就能执行';

/** An Agent's draft of a credential and the connections using it. The Owner enters the credential values
 * here, once for all of them, and approves or denies the draft as it stands; nothing on the card edits it. */
function SetupCard({ app, request, setup }: { app: AppApi; request: Pending; setup: Setup }) {
  const { secret, connections } = setup;
  const created = secret ? '凭据和连接' : '连接';
  // A value goes only where a connection's auth names its field: the origins of those connections.
  const originsOf = (field: string) => [
    ...new Set(
      connections
        .filter(({ auth }) =>
          auth.type === 'basic'
            ? [auth.usernameField, auth.passwordField].includes(field)
            : auth.type !== 'none' && auth.field === field,
        )
        .map((c) => c.origin),
    ),
  ];
  const unused = '草案里没有连接使用这个字段，只保存';
  const deny = useDeny(app, request, secret ? '凭据和连接都不会创建，' : '连接不会创建，');
  return (
    <PendingShell
      title={`${clientName(app.status, request.client_id)} 申请新建${created}`}
      request={request}
      lead={<Delivery setup={setup} />}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          const values = secret ? Object.fromEntries(secret.fields.map((field) => [field, fv(f, field)])) : null;
          void app.run(async () => {
            await api(`/admin/access-requests/${request.id}/approve`, 'POST', values ? { values } : undefined);
            await app.refresh();
          }, `已批准，${created}已创建。Agent 查询申请状态即可拿到连接 ID；使用连接仍需授权，免审批规则内的请求除外。`);
        }}
      >
        {secret ? (
          <dl className="request-call">
            <dt>凭据</dt>
            <dd>
              {secret.name}
              {secret.description ? <span className="muted"> · {secret.description}</span> : null}
            </dd>
            {secret.fields.map((field) => {
              const origins = originsOf(field);
              return (
                <Fragment key={field}>
                  <dt className="mono">{field}</dt>
                  {/* Where the value goes stays in view where the Owner pastes it, every origin wrapped
                      whole: a cut one would show only the part an Agent can make look trustworthy. */}
                  <dd className="request-value">
                    <input
                      name={field}
                      type="password"
                      autoComplete="off"
                      required
                      aria-label={`凭据字段 ${field} 的值，${origins.length ? `将发往 ${origins.join('、')}` : unused}`}
                    />
                    <span className="small">
                      {origins.length ? '将发往 ' : unused}
                      {origins.map((origin, i) => (
                        <Fragment key={origin}>
                          {i ? '、' : ''}
                          <code>{origin}</code>
                        </Fragment>
                      ))}
                    </span>
                  </dd>
                </Fragment>
              );
            })}
          </dl>
        ) : null}
        {/* Each connection folds on its own, so a draft of many stays readable; the origin stays in the
            line that remains. It stands before the name, which the Agent wrote: isolated, a direction
            override in the name cannot reorder the origin, and no made-up address can precede it. */}
        {connections.map((c, i) => (
          <details className="request-connection" key={i} open>
            <summary>
              连接 {i + 1}/{connections.length} · <code>{c.origin}</code> · <bdi>{c.name}</bdi>
            </summary>
            <dl className="request-call">
              <dt>允许路径</dt>
              <dd>
                <Lines items={c.paths} />
              </dd>
              <dt>允许方法</dt>
              <dd className="mono">{c.methods.join(' ')}</dd>
              {(['deny', 'approval', 'free'] as const).map((kind) => (
                <Fragment key={kind}>
                  <dt>{ruleKindText[kind]}规则</dt>
                  <dd>
                    <Lines items={c[kind]} />
                  </dd>
                </Fragment>
              ))}
              <dt>额外域名</dt>
              <dd>
                <Lines items={c.hosts ?? []} />
              </dd>
              <dt>给 Agent 的说明</dt>
              <dd>{c.description || '无'}</dd>
              <dt>测试</dt>
              <dd>
                <p className="small muted">提交时已用这条连接的草案策略逐条试跑，全部符合 Agent 的预期。</p>
                <TestTable tests={c.tests} />
              </dd>
            </dl>
          </details>
        ))}
        <p className="small muted">
          批准后服务端一次建好{created}
          {secret ? '，凭据值加密保存、不会交给 Agent' : ''}；不附带授权
          {connections.some((c) => c.free.length) ? `，但${freeText}${secret ? '，并会注入这份凭据' : ''}` : ''}
          。申请将在 {relativeText(request.expires_at)}失效。
        </p>
        <div className="alert-actions">
          <button className="btn btn--small" disabled={app.busy}>
            批准并创建
          </button>
          <button type="button" className="btn btn--ghost btn--small" disabled={app.busy} onClick={() => void deny()}>
            拒绝
          </button>
        </div>
      </form>
    </PendingShell>
  );
}

/** Lines before and after an update: a removed line is marked −, an added one +, the rest stay plain.
 * Paths and rules show escaped like a request; a name or a note is plain text. */
function LineDiff({ before, after, text = false }: { before: string[]; after: string[]; text?: boolean }) {
  const rows = [
    ...before.filter((line) => !after.includes(line)).map((line) => ['−', line] as const),
    ...after.map((line) => [before.includes(line) ? ' ' : '+', line] as const),
  ];
  return (
    <ul className={text ? 'request-diff' : 'request-diff mono'}>
      {rows.map(([mark, line], i) => (
        <li key={i} className={mark === '−' ? 'diff-del' : mark === '+' ? 'diff-add' : undefined}>
          {mark} {text ? line || '（空）' : <Visible text={line} />}
        </li>
      ))}
    </ul>
  );
}
const CHANGES = [
  ['name', '名称'],
  ['description', '给 Agent 的说明'],
  ['paths', '允许路径'],
  ['methods', '允许方法'],
  ['deny', `${ruleKindText.deny}规则`],
  ['approval', `${ruleKindText.approval}规则`],
  ['free', `${ruleKindText.free}规则`],
] as const;

/** An Agent's changes to a connection, compared with the connection as it was when they were submitted.
 * Approval requires it unchanged since, so once it changed the card only offers to deny. */
function UpdateCard({
  app,
  request,
  update,
  current,
  updatedAt,
}: {
  app: AppApi;
  request: Pending;
  update: Update;
  current: string[];
  updatedAt: number;
}) {
  const connection = app.status.connections.find((c) => c.id === update.connection);
  const changed = connection?.updated_at !== updatedAt;
  const before = {
    name: connection?.name ?? '',
    description: connection?.description ?? '',
    methods: ['GET', 'HEAD'],
    deny: [],
    approval: [],
    free: [],
    ...(connection ? parsePolicy(connection) : { paths: [] }),
  };
  // Every list but the name and the notes bears on what a free rule runs without a grant: the free rules
  // themselves, the scope they apply in, and the deny and approval rules that come before them.
  const freeReach =
    (update.changes.free ?? before.free).length > 0 &&
    Object.keys(update.changes).some((key) => key !== 'name' && key !== 'description');
  const injects = !!connection && parseAuth(connection).type !== 'none';
  const deny = useDeny(app, request, '连接保持不变，');
  const approve = () =>
    app.run(async () => {
      await api(`/admin/access-requests/${request.id}/approve`, 'POST');
      await app.refresh();
    }, '已批准，连接已按草案修改。');
  return (
    <PendingShell
      title={`${clientName(app.status, request.client_id)} 申请修改连接「${connection?.name ?? update.connection}」`}
      request={request}
    >
      {changed ? (
        <p className="request-delivery">
          这条连接在申请提交后又被修改或已删除，下面的对比不再成立，只能拒绝；Agent 可以按现状重新提交。
        </p>
      ) : (
        <p className="small muted">服务地址和凭据注入方式不变，只改下列项目。</p>
      )}
      <dl className="request-call">
        {CHANGES.map(([key, label]) => {
          const after = update.changes[key];
          if (after === undefined) return null;
          return (
            <Fragment key={key}>
              <dt>{label}</dt>
              <dd>
                {typeof after === 'string' ? (
                  <LineDiff before={[before[key] as string]} after={[after]} text />
                ) : (
                  <LineDiff before={before[key] as string[]} after={after} />
                )}
              </dd>
            </Fragment>
          );
        })}
        <dt>测试</dt>
        <dd>
          <p className="small muted">提交时已用修改后的策略逐条试跑，全部符合 Agent 的预期；标出的是结果会变的请求。</p>
          <TestTable tests={update.tests} current={current} />
        </dd>
      </dl>
      <p className="small muted">
        批准不附带授权
        {freeReach ? `，但修改后${freeText}${injects ? '，并会注入连接绑定的凭据' : ''}` : ''}。申请将在{' '}
        {relativeText(request.expires_at)}失效。
      </p>
      <div className="alert-actions">
        <button type="button" className="btn btn--small" disabled={app.busy || changed} onClick={() => void approve()}>
          批准修改
        </button>
        <button type="button" className="btn btn--ghost btn--small" disabled={app.busy} onClick={() => void deny()}>
          拒绝
        </button>
      </div>
    </PendingShell>
  );
}

export function Access({ app }: { app: AppApi }) {
  const [open, setOpen] = useState(false);
  const [resource, setResource] = useState('');
  const confirm = useConfirm();
  const { secrets, connections, clients, grants, pending } = app.status;
  const activeClients = clients.filter((c) => !c.disabled && c.userId);
  const resources = [
    ...secrets.map((s) => ({ value: `secret:${s.id}`, label: `凭据 · ${s.name}` })),
    ...connections.map((c) => ({ value: `connection:${c.id}`, label: `API 连接 · ${c.name}` })),
  ];

  const revoke = async (g: Grant) => {
    const ok = await confirm({
      title: '撤销授权',
      body: `${clientName(app.status, g.client_id)} 将立即失去对“${resourceName(app.status, g.resource_id)}”的访问。已经交给程序的凭据无法追回。`,
      confirmLabel: '撤销授权',
      danger: true,
    });
    if (!ok) return;
    await app.run(async () => {
      await api('/admin/grants/' + g.id, 'DELETE');
      await app.refresh();
    }, '授权已撤销。');
  };

  return (
    <>
      <PageHead
        title="资源授权"
        description="授权决定某个安装实例能使用哪些凭据和连接。只授予完成任务所需的资源，并优先设置有效期。"
        actions={
          <>
            <RefreshButton app={app} />
            <button
              type="button"
              className="btn"
              disabled={app.busy || !activeClients.length || !resources.length}
              onClick={() => {
                setResource('');
                setOpen(true);
              }}
            >
              <Icon name="plus" size={16} />
              新增授权
            </button>
          </>
        }
      />
      {pending.length ? (
        <Panel
          title="待批准的申请"
          description="资源授权申请：批准只新增或恢复授权，不改变已有有效授权的字段范围，也不缩短它的有效期；申请里的临时扩展范围按这次选的有效期并入已有扩展。单次请求申请：批准后 10 分钟内可原样执行一次，不产生长期授权。新建和修改连接的草案：只能整份批准或拒绝，新建时在卡片上填入凭据值；两者都不附带授权。"
        >
          <div className="panel-body alerts">
            {pending.map((p) => (
              <PendingCard key={p.id} app={app} request={p} />
            ))}
          </div>
        </Panel>
      ) : null}
      <Panel title="生效中的授权">
        {app.loading ? (
          <Loading />
        ) : grants.length ? (
          <div className="rows">
            {grants.map((g) => (
              <div className="row" key={g.id}>
                <div className="row-main">
                  <div className="row-title">
                    <h3>
                      {clientName(app.status, g.client_id)} → {resourceName(app.status, g.resource_id)}
                    </h3>
                    <Badge tone={g.resource_type === 'secret' ? 'accent' : 'neutral'}>
                      {g.resource_type === 'secret' ? 'secret:read' : 'connection:invoke'}
                    </Badge>
                    {isExpiringSoon(g) ? <Badge tone="warn">即将过期</Badge> : null}
                  </div>
                  <p className="row-meta">{permissionText(g)}</p>
                  {g.extensions.map((e, i) => (
                    <p className="row-meta" key={i}>
                      临时扩展：
                      <ExtensionScope paths={e.paths} methods={e.methods} />（
                      {e.expiresAt ? `${timeText(e.expiresAt)} 到期` : '与授权同时结束'}）
                    </p>
                  ))}
                  <p className="row-meta">
                    {g.expires_at ? `${timeText(g.expires_at)} 到期（${relativeText(g.expires_at)}）` : '直到手动撤销'}
                  </p>
                </div>
                <div className="row-actions">
                  <button
                    type="button"
                    className="btn btn--danger btn--small"
                    disabled={app.busy}
                    onClick={() => void revoke(g)}
                  >
                    撤销
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            title="当前没有生效的资源授权"
            description="安装实例登录后仍然看不到任何资源，直到你在这里授予凭据或连接。"
          />
        )}
      </Panel>

      <Drawer
        open={open}
        title="新增授权"
        description="需要 10 分钟内的登录。同一资源再次授权：有效期只会延长；字段范围和临时扩展范围以本次填写为准。"
        onClose={() => setOpen(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void app.run(async () => {
              const [type, rid] = fv(f, 'resource').split(':');
              const fields = f.getAll('fields').map(String);
              const paths = lines(fv(f, 'paths'));
              const methods = f.getAll('methods').map(String);
              await api('/admin/grants', 'POST', {
                clientId: fv(f, 'clientId'),
                grants: [
                  {
                    resourceType: type,
                    resourceId: rid,
                    permission: type === 'secret' ? 'secret:read' : 'connection:invoke',
                    ...(type === 'secret' && fields.length ? { fields } : {}),
                    ...(type === 'connection' && paths.length ? { paths } : {}),
                    ...(type === 'connection' && methods.length ? { methods } : {}),
                  },
                ],
                expiresAt: expiresAtFor(fv(f, 'duration')),
              });
              setOpen(false);
              await app.refresh();
            }, '已授予资源权限。');
          }}
        >
          <Field label="安装实例">
            <select name="clientId" required>
              {activeClients.map((c) => (
                <option key={c.clientId} value={c.clientId}>
                  {c.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="允许使用的资源">
            <select name="resource" required value={resource} onChange={(e) => setResource(e.target.value)}>
              <option value="">请选择</option>
              {resources.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </select>
          </Field>
          {resource.startsWith('secret:') ? (
            <fieldset key={resource}>
              <legend>可读字段</legend>
              <div className="check-grid">
                {app.status.secrets
                  .find((s) => 'secret:' + s.id === resource)
                  ?.fields.map((name) => (
                    <label className="check" key={name}>
                      <input type="checkbox" name="fields" value={name} />
                      <span className="mono">{name}</span>
                    </label>
                  ))}
              </div>
              <p className="field-hint">都不勾表示该凭据的全部字段，包括以后新增的字段。</p>
            </fieldset>
          ) : null}
          {resource.startsWith('connection:') ? (
            <>
              <p className="note">
                临时扩展范围（可选）：让这个实例在授权期内调用连接允许范围之外的路径或方法，不改动连接本身，撤销或到期即失效。拒绝和必须单次审批规则照样生效。再次授权时以本次填写为准，留空会清除已有扩展。
              </p>
              <Field
                label="扩展路径前缀"
                hint="每行一个，写法同连接的允许路径。路径留空表示连接现在允许的路径，方法不勾表示连接现在允许的方法，授权时固定下来，之后改连接不影响。"
              >
                <textarea name="paths" rows={2} placeholder="/client/v4/user/tokens" />
              </Field>
              <fieldset>
                <legend>扩展方法</legend>
                <div className="check-grid">
                  {METHODS.map((m) => (
                    <label className="check" key={m}>
                      <input type="checkbox" name="methods" value={m} />
                      <span>{m}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
            </>
          ) : null}
          <Field label="有效期" hint="测试用途建议 24 小时。到期后 Agent 需重新申请。">
            <select name="duration" defaultValue="86400000">
              {durationOptions}
            </select>
          </Field>
          <div className="form-actions">
            <button className="btn" disabled={app.busy}>
              授予资源权限
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => setOpen(false)}>
              取消
            </button>
          </div>
        </form>
      </Drawer>
    </>
  );
}
