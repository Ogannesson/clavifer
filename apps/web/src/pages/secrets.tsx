import { useState } from 'react';
import { api, fv, timeText, type Secret } from '../api';
import { PageHead, RefreshButton, type AppApi } from '../shell';
import { Badge, Drawer, EmptyState, Field, Icon, Loading, Panel, useConfirm } from '../ui';

type Editing = { secret: Secret | null } | null;

export function Secrets({ app }: { app: AppApi }) {
  const [editing, setEditing] = useState<Editing>(null);
  const [rows, setRows] = useState<number[]>([0]);
  const confirm = useConfirm();
  const secret = editing?.secret ?? null;

  const openEditor = (target: Secret | null) => {
    setRows([0]);
    setEditing({ secret: target });
  };

  const remove = async (s: Secret) => {
    const ok = await confirm({
      title: `删除凭据「${s.name}」`,
      body: '删除会在同一事务中清除该凭据的全部版本密文，包括历史版本；此后只能从删除之前的备份恢复。仍被 API 连接引用的凭据无法删除。',
      confirmLabel: '永久删除',
      danger: true,
    });
    if (!ok) return;
    await app.run(async () => {
      await api('/admin/secrets/' + s.id, 'DELETE');
      await app.refresh();
    }, '凭据及其全部版本密文已删除。');
  };

  return (
    <>
      <PageHead
        title="凭据"
        description="值加密保存，保存后不在网页中显示明文。轮换只更新本服务保存的值，不会替你更换提供方的 API Key。"
        actions={
          <>
            <RefreshButton app={app} />
            <button type="button" className="btn" disabled={app.busy} onClick={() => openEditor(null)}>
              <Icon name="plus" size={16} />
              添加凭据
            </button>
          </>
        }
      />
      <Panel>
        {app.loading ? (
          <Loading />
        ) : app.status.secrets.length ? (
          <div className="rows">
            {app.status.secrets.map((s) => (
              <div className="row" key={s.id}>
                <div className="row-main">
                  <div className="row-title">
                    <h3>{s.name}</h3>
                    <Badge>版本 {s.current_version}</Badge>
                  </div>
                  <p className="row-meta">{s.description || '没有填写用途说明。'}</p>
                  <p className="row-meta">
                    字段 <span className="mono">{s.fields.join('、')}</span>
                  </p>
                  <p className="row-meta">
                    更新于 {timeText(s.updated_at)} · <span className="mono">{s.id}</span>
                  </p>
                </div>
                <div className="row-actions">
                  <button
                    type="button"
                    className="btn btn--ghost btn--small"
                    disabled={app.busy}
                    onClick={() => openEditor(s)}
                  >
                    轮换 / 编辑
                  </button>
                  <button
                    type="button"
                    className="btn btn--danger btn--small"
                    disabled={app.busy}
                    onClick={() => void remove(s)}
                  >
                    删除
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            title="还没有凭据"
            description="先添加一项凭据，再用它配置 API 连接或直接授权给安装实例。"
            action={
              <button type="button" className="btn" onClick={() => openEditor(null)}>
                添加凭据
              </button>
            }
          />
        )}
      </Panel>

      <Drawer
        open={!!editing}
        title={secret ? `轮换「${secret.name}」` : '添加凭据'}
        description={
          secret
            ? '保存后版本加一，只填写需要更新的字段，其余字段保持原值。若期间凭据已被他处更新，保存会被拒绝。'
            : '字段名用于连接绑定与按字段授权，例如 token、username、password。'
        }
        onClose={() => setEditing(null)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void app.run(
              async () => {
                const names = f.getAll('field').map((v) => String(v).trim());
                if (new Set(names).size !== names.length) throw new Error('字段名称不能重复。');
                const values = Object.fromEntries(names.map((name, i) => [name, String(f.getAll('value')[i] ?? '')]));
                await api(secret ? '/admin/secrets/' + secret.id : '/admin/secrets', secret ? 'PUT' : 'POST', {
                  name: fv(f, 'name').trim(),
                  description: fv(f, 'description'),
                  values,
                  ...(secret ? { expectedVersion: secret.current_version } : {}),
                });
                setEditing(null);
                await app.refresh();
              },
              secret ? '凭据已轮换到新版本。' : '凭据已保存。',
            );
          }}
        >
          <Field label="名称">
            <input name="name" maxLength={120} required defaultValue={secret?.name ?? ''} />
          </Field>
          <Field label="用途说明" hint="只用于你自己辨认，不会发送给上游。">
            <input name="description" maxLength={1000} defaultValue={secret?.description ?? ''} />
          </Field>
          <fieldset>
            <legend>字段</legend>
            {rows.map((row, index) => (
              <div className="field-row" key={row}>
                <Field label="字段名称">
                  <input
                    name="field"
                    required
                    list="secret-fields"
                    pattern="[A-Za-z_][A-Za-z0-9_\-]*"
                    defaultValue={index === 0 && !secret ? 'token' : ''}
                  />
                </Field>
                <Field label="凭据值">
                  <input name="value" type="password" autoComplete="off" required />
                </Field>
                {index === 0 ? null : (
                  <button
                    type="button"
                    className="btn btn--quiet"
                    onClick={() => setRows((list) => list.filter((r) => r !== row))}
                  >
                    移除
                  </button>
                )}
              </div>
            ))}
            <button
              type="button"
              className="btn btn--ghost btn--small"
              onClick={() => setRows((list) => [...list, (list.at(-1) ?? 0) + 1])}
            >
              <Icon name="plus" size={15} />
              增加字段
            </button>
            <datalist id="secret-fields">
              {secret?.fields.map((name) => (
                <option key={name} value={name} />
              ))}
            </datalist>
            <p className="field-hint">
              {secret ? `现有字段：${secret.fields.join('、')}；填新字段名会新增该字段。` : ''}
              最多 20 个字段，字段名以字母或下划线开头。
            </p>
          </fieldset>
          <div className="form-actions">
            <button className="btn" disabled={app.busy}>
              {secret ? '保存新版本' : '保存凭据'}
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
