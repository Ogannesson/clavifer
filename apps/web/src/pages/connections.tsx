import { useState } from 'react';
import {
  api,
  authTypeText,
  fv,
  hostedSuffixText,
  lines,
  METHODS,
  parseAuth,
  parsePolicy,
  resourceName,
  type Connection,
  type ConnectionAuth,
  type ConnectionPolicy,
} from '../api';
import { PageHead, RefreshButton, type AppApi } from '../shell';
import { Badge, Drawer, EmptyState, Field, Icon, Loading, Panel, useConfirm } from '../ui';

const boundSecretId = (auth: ConnectionAuth) => (auth.type === 'none' ? null : auth.secretId);
/** The three rule lists share one format; the order here is the order the server applies them. */
const RULES = [
  {
    name: 'deny',
    label: '拒绝',
    hint: '唯一的绝对禁止：命中即拒绝，已有授权、临时扩展或单次批准都不能执行，Agent 会看到命中的规则原文。只写路径表示任意方法（* 路径）。',
    placeholder: '/v1/accounts/important/*',
  },
  {
    name: 'approval',
    label: '必须单次审批',
    hint: '命中时时长授权和临时扩展都无效，每次都要你批准这一个具体请求；允许范围内外都生效。只写路径表示任意方法（* 路径）。',
    placeholder: 'DELETE /v1/items/*',
  },
  {
    name: 'free',
    label: '免审批',
    hint: '只在允许的路径和方法之内生效：命中时无需任何授权即可执行（仍记审计）。只写路径表示只读（GET 路径，含 HEAD）；写别的方法须显式写出。',
    placeholder: '/v1/public/*',
  },
] as const;

/** Offers only the bound credential's own fields: keeps the given name if the credential has it, else its only field. */
function FieldSelect({ name, fields, value }: { name: string; fields: string[]; value: string }) {
  return (
    <select name={name} required defaultValue={fields.includes(value) ? value : fields.length === 1 ? fields[0] : ''}>
      <option value="">请选择</option>
      {fields.map((f) => (
        <option key={f} value={f}>
          {f}
        </option>
      ))}
    </select>
  );
}

export function Connections({ app }: { app: AppApi }) {
  const [editing, setEditing] = useState<{ connection: Connection | null } | null>(null);
  const [authType, setAuthType] = useState('none');
  const [secretId, setSecretId] = useState('');
  const confirm = useConfirm();
  const connection = editing?.connection ?? null;
  const auth = connection ? parseAuth(connection) : null;
  const policy = connection ? parsePolicy(connection) : null;
  const fields = app.status.secrets.find((s) => s.id === secretId)?.fields ?? [];

  const openEditor = (target: Connection | null) => {
    setAuthType(target ? parseAuth(target).type : 'none');
    setSecretId((target && boundSecretId(parseAuth(target))) ?? '');
    setEditing({ connection: target });
  };

  const remove = async (c: Connection) => {
    const ok = await confirm({
      title: `删除连接「${c.name}」`,
      body: '删除会同时撤销所有针对这条连接的授权，正在使用它的 Agent 会立即收到拒绝。绑定的凭据本身不受影响。',
      confirmLabel: '删除连接',
      danger: true,
    });
    if (!ok) return;
    await app.run(async () => {
      await api('/admin/connections/' + c.id, 'DELETE');
      await app.refresh();
    }, '连接已删除，相关授权已撤销。');
  };

  // Connections that bind the same credential fold into one block, placed where the first of them
  // stands in the server's order; a credential with one connection, and a connection without one,
  // stay as they are.
  const members = (sid: string | null) =>
    sid ? app.status.connections.filter((c) => boundSecretId(parseAuth(c)) === sid) : [];
  // Everything a connection's card says below its address; in a group it sits behind the row's details.
  const particulars = (c: Connection, p: ConnectionPolicy) => (
    <>
      {c.description ? <p className="row-meta">说明：{c.description}</p> : null}
      <p className="row-meta">
        {(p.methods ?? ['GET', 'HEAD']).join(' ')} · 路径 {p.paths.join('、')}
      </p>
      {/* Rules as the server normalized them, so a bare path shows the method it received. */}
      {RULES.map((r) =>
        p[r.name]?.length ? (
          <p className="row-meta" key={r.name}>
            {r.label} {p[r.name]!.length} 条：<span className="mono">{p[r.name]!.join('、')}</span>
          </p>
        ) : null,
      )}
      {p.hosts?.length ? (
        <p className="row-meta">
          额外域名 {p.hosts.length} 条（须单次审批）：<span className="mono">{p.hosts.join('、')}</span>
        </p>
      ) : null}
      {p.anyHost ? (
        <p className="row-meta">
          <Badge tone="warn">可经单次审批发往任意地址</Badge>
        </p>
      ) : null}
      <p className="row-meta mono">{c.id}</p>
    </>
  );
  const actions = (c: Connection) => (
    <div className="row-actions">
      <button type="button" className="btn btn--ghost btn--small" disabled={app.busy} onClick={() => openEditor(c)}>
        编辑
      </button>
      <button type="button" className="btn btn--danger btn--small" disabled={app.busy} onClick={() => void remove(c)}>
        删除
      </button>
    </div>
  );

  return (
    <>
      <PageHead
        title="API 连接"
        description="Agent 只能使用这里指定的服务、路径和方法；凭据由服务端注入，不会交给 Agent。上游服务必须可信，因为它会收到绑定凭据。"
        actions={
          <>
            <RefreshButton app={app} />
            <button type="button" className="btn" disabled={app.busy} onClick={() => openEditor(null)}>
              <Icon name="plus" size={16} />
              添加连接
            </button>
          </>
        }
      />
      <Panel>
        {app.loading ? (
          <Loading />
        ) : app.status.connections.length ? (
          <div className="rows">
            {app.status.connections.map((c) => {
              const a = parseAuth(c);
              const p = parsePolicy(c);
              const bound = boundSecretId(a);
              const group = members(bound);
              if (group.length < 2)
                return (
                  <div className="row" key={c.id}>
                    <div className="row-main">
                      <div className="row-title">
                        <h3>{c.name}</h3>
                        <Badge tone={a.type === 'none' ? 'neutral' : 'accent'}>{authTypeText[a.type]}</Badge>
                        {bound ? <Badge>凭据 · {resourceName(app.status, bound)}</Badge> : null}
                      </div>
                      <p className="row-meta mono">{c.origin}</p>
                      {particulars(c, p)}
                    </div>
                    {actions(c)}
                  </div>
                );
              if (group[0] !== c) return null;
              // Folded by default and not remounted by a refresh, so what the Owner opened stays open
              // while the page does. The folded line names the credential and every address it goes to.
              return (
                <details className="row-group" key={bound}>
                  <summary className="row">
                    <div className="row-main">
                      <div className="row-title">
                        <h3>{resourceName(app.status, bound!)}</h3>
                        <Badge>凭据 · {group.length} 条连接</Badge>
                      </div>
                      <p className="row-meta mono">{[...new Set(group.map((m) => m.origin))].join('、')}</p>
                    </div>
                  </summary>
                  <div className="rows">
                    {group.map((m) => {
                      const auth = parseAuth(m);
                      const policy = parsePolicy(m);
                      return (
                        <div className="row" key={m.id}>
                          <div className="row-main">
                            <div className="row-title">
                              <h3>{m.name}</h3>
                              <Badge tone="accent">{authTypeText[auth.type]}</Badge>
                              {policy.hosts?.length ? (
                                <Badge tone="warn">额外域名 {policy.hosts.length} 条</Badge>
                              ) : null}
                              {policy.anyHost ? <Badge tone="warn">任意地址</Badge> : null}
                            </div>
                            <p className="row-meta">
                              <span className="mono">{m.origin}</span> · {(policy.methods ?? ['GET', 'HEAD']).join(' ')}{' '}
                              · {RULES.map((r) => `${r.label} ${policy[r.name]?.length ?? 0}`).join(' · ')}
                            </p>
                            <details className="row-details">
                              <summary>详情</summary>
                              <div>{particulars(m, policy)}</div>
                            </details>
                          </div>
                          {actions(m)}
                        </div>
                      );
                    })}
                  </div>
                </details>
              );
            })}
          </div>
        ) : (
          <EmptyState
            title="还没有 API 连接"
            description="连接把一条凭据绑定到一个可信上游，Agent 只需获得 connection:invoke 授权即可调用，看不到凭据原文。"
            action={
              <button type="button" className="btn" onClick={() => openEditor(null)}>
                添加连接
              </button>
            }
          />
        )}
      </Panel>

      <Drawer
        open={!!editing}
        title={connection ? `编辑「${connection.name}」` : '添加 API 连接'}
        description="保存连接需要 10 分钟内的登录：它决定哪个上游收到哪条凭据。编辑会保留已有授权。"
        onClose={() => setEditing(null)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void app.run(async () => {
              const methods = f.getAll('methods').map(String);
              if (!methods.length) throw new Error('至少勾选一个允许的方法。');
              const type = fv(f, 'type');
              const secretId = fv(f, 'secretId');
              const binding: ConnectionAuth =
                type === 'none'
                  ? { type: 'none' }
                  : type === 'basic'
                    ? {
                        type: 'basic',
                        secretId,
                        usernameField: fv(f, 'usernameField').trim(),
                        passwordField: fv(f, 'passwordField').trim(),
                      }
                    : type === 'bearer'
                      ? { type: 'bearer', secretId, field: fv(f, 'field').trim() }
                      : {
                          type: type === 'header' ? 'header' : 'query',
                          secretId,
                          field: fv(f, 'field').trim(),
                          name: fv(f, 'headerName').trim(),
                        };
              await api('/admin/connections' + (connection ? '/' + connection.id : ''), connection ? 'PUT' : 'POST', {
                name: fv(f, 'name').trim(),
                origin: fv(f, 'origin').trim(),
                description: fv(f, 'description').trim(),
                paths: lines(fv(f, 'paths')),
                methods,
                deny: lines(fv(f, 'deny')),
                approval: lines(fv(f, 'approval')),
                free: lines(fv(f, 'free')),
                hosts: lines(fv(f, 'hosts')),
                anyHost: f.has('anyHost'),
                auth: binding,
              });
              setEditing(null);
              await app.refresh();
            }, '连接已保存。');
          }}
        >
          <Field label="名称">
            <input name="name" maxLength={120} required defaultValue={connection?.name ?? ''} />
          </Field>
          <Field label="服务地址" hint="只填 origin，例如 https://api.example.com；路径前缀在下面单独填写。">
            <input
              name="origin"
              type="url"
              placeholder="https://api.example.com"
              required
              defaultValue={connection?.origin ?? ''}
            />
          </Field>
          <Field
            label="给 Agent 的说明"
            hint="所有安装实例都能在 credentials.list 里看到，例如每个请求必须带的非机密请求头、资源 ID 从哪个接口查。不要写密钥。"
          >
            <textarea
              name="description"
              rows={2}
              maxLength={2000}
              placeholder="每个请求带 X-Account: example；账户 ID 用 GET /v1/accounts 查。"
              defaultValue={connection?.description ?? ''}
            />
          </Field>
          <Field
            label="允许的路径前缀"
            hint="每行一个。/v1 允许 /v1/items，不允许 /v10；不要使用星号。允许的路径和方法构成常规范围：范围外的请求要你单次批准，或批准带临时扩展范围的授权。"
          >
            <textarea name="paths" rows={3} placeholder="/v1" required defaultValue={policy?.paths.join('\n') ?? ''} />
          </Field>
          <fieldset>
            <legend>允许的方法</legend>
            <div className="check-grid">
              {METHODS.map((m) => (
                <label className="check" key={m}>
                  <input
                    type="checkbox"
                    name="methods"
                    value={m}
                    defaultChecked={(policy?.methods ?? ['GET', 'HEAD']).includes(m)}
                  />
                  <span>{m}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <p className="note">
            下面三类规则每行一条，格式为「方法 路径」：方法写 GET、POST 等或 *（任意方法），GET 同时覆盖
            HEAD；也可以只写路径，保存时补成默认方法（见各栏说明）。路径以 / 开头，默认精确匹配，末尾写 /*
            表示该路径及其所有子路径。匹配不区分英文大小写，不看查询串，按解码后的路径比较（段内的 %2F 视为斜杠）。
          </p>
          {RULES.map((r) => (
            <Field key={r.name} label={`${r.label}规则`} hint={r.hint}>
              <textarea
                name={r.name}
                rows={2}
                placeholder={r.placeholder}
                defaultValue={policy?.[r.name]?.join('\n') ?? ''}
              />
            </Field>
          ))}
          <Field
            label="额外域名"
            hint={`每行一个域名（artifacts.example.com）或 *.后缀（*.example.com，含任意层级的子域名，不含后缀本身），不带 https://、端口和路径。Agent 可以申请把这条连接的某一个请求发往这些域名，每个请求都要你单次批准，时长授权和免审批规则在那里不生效。${hostedSuffixText}`}
          >
            <textarea
              name="hosts"
              rows={2}
              placeholder="*.example.com"
              defaultValue={policy?.hosts?.join('\n') ?? ''}
            />
          </Field>
          <label className="check">
            <input type="checkbox" name="anyHost" defaultChecked={policy?.anyHost ?? false} />
            <span>允许经单次审批发往任意地址</span>
          </label>
          <p className="note">
            勾选后，Agent 可以申请把这条连接的请求发往任何公网 HTTPS
            地址，凭据会随请求一起注入。每个请求仍要你单次批准，但地址由 Agent
            提出：批准一个你不认识的地址，就是把这份凭据交给它的运营者。能用额外域名列出范围时不要勾选。
          </p>
          <Field label="凭据注入方式">
            <select name="type" value={authType} onChange={(e) => setAuthType(e.target.value)}>
              {Object.entries(authTypeText).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
          {authType === 'none' ? (
            <p className="note">不注入任何凭据，代理只做路径与方法限制。</p>
          ) : (
            <>
              <Field label="绑定凭据">
                <select name="secretId" required value={secretId} onChange={(e) => setSecretId(e.target.value)}>
                  <option value="">请选择</option>
                  {app.status.secrets.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </Field>
              {authType === 'basic' ? (
                <div className="field-row field-row--pair">
                  <Field label="用户名字段">
                    <FieldSelect
                      key={secretId}
                      name="usernameField"
                      fields={fields}
                      value={auth?.type === 'basic' ? auth.usernameField : 'username'}
                    />
                  </Field>
                  <Field label="密码字段">
                    <FieldSelect
                      key={secretId}
                      name="passwordField"
                      fields={fields}
                      value={auth?.type === 'basic' ? auth.passwordField : 'password'}
                    />
                  </Field>
                </div>
              ) : (
                <Field label="字段名称" hint="从绑定凭据的字段中选择，连接本身不保存密钥值。">
                  <FieldSelect
                    key={secretId}
                    name="field"
                    fields={fields}
                    value={auth && 'field' in auth ? auth.field : 'token'}
                  />
                </Field>
              )}
              {authType === 'header' || authType === 'query' ? (
                <Field
                  label={authType === 'header' ? '请求头名称' : 'URL 参数名称'}
                  hint={
                    authType === 'header'
                      ? '例如 X-API-Key。调用者不能覆盖注入的请求头。'
                      : '例如 api_key。提供方可能把 URL 写进日志，仅在 API 明确要求时使用。'
                  }
                >
                  <input
                    name="headerName"
                    required
                    placeholder={authType === 'header' ? 'X-API-Key' : 'api_key'}
                    defaultValue={auth && 'name' in auth ? auth.name : ''}
                  />
                </Field>
              ) : null}
            </>
          )}
          <div className="form-actions">
            <button className="btn" disabled={app.busy}>
              保存连接
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => setEditing(null)}>
              取消
            </button>
          </div>
        </form>
      </Drawer>
    </>
  );
}
