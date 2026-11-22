import { useState } from 'react';
import { api, fv, timeText, type Secret } from '../api';
import { PageHead, RefreshButton, type AppApi } from '../shell';
import { Badge, Drawer, EmptyState, Field, Icon, Loading, Panel, useConfirm } from '../ui';
import { FileButton, lockedKey, readText, ValueInput } from '../value-input';
import { jsonFields } from '../values';

type Editing = { secret: Secret | null } | null;
/** One field of the form; key stays with the row while its name and value change. */
type Row = { key: number; field: string; value: string };

export function Secrets({ app }: { app: AppApi }) {
  const [editing, setEditing] = useState<Editing>(null);
  const [rows, setRows] = useState<Row[]>([]);
  const confirm = useConfirm();
  const secret = editing?.secret ?? null;

  const openEditor = (target: Secret | null) => {
    setRows([{ key: 0, field: target ? '' : 'token', value: '' }]);
    setEditing({ secret: target });
  };
  const update = (key: number, change: Partial<Row>) =>
    setRows((list) => list.map((r) => (r.key === key ? { ...r, ...change } : r)));
  // A JSON file sets the value of a row of the same name and adds a row for every other name; a row
  // without a value (the blank one the form opens with) gives way to them.
  const fill = (file: File) =>
    void app.run(async () => {
      const { fields, notice } = await jsonFields(await readText(file));
      setRows((list) => {
        const kept = list
          .filter((r) => r.value || Object.hasOwn(fields, r.field))
          .map((r) => (Object.hasOwn(fields, r.field) ? { ...r, value: fields[r.field] } : r));
        let next = Math.max(0, ...list.map((r) => r.key)) + 1;
        const added = Object.entries(fields)
          .filter(([name]) => !kept.some((r) => r.field === name))
          .map(([field, value]) => ({ key: next++, field, value }));
        return [...kept, ...added];
      });
      app.notify(notice);
    }, '');

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
                const names = rows.map((r) => r.field.trim());
                if (new Set(names).size !== names.length) throw new Error('字段名称不能重复。');
                const locked = rows.filter((r) => lockedKey(r.value)).map((r) => r.field);
                if (locked.length) throw new Error(`字段 ${locked.join('、')} 还是带口令的私钥，请先输入口令解开。`);
                const values = Object.fromEntries(rows.map((r, i) => [names[i], r.value]));
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
              <div className="field-row" key={row.key}>
                <Field label="字段名称">
                  <input
                    name="field"
                    required
                    list="secret-fields"
                    pattern="[A-Za-z_][A-Za-z0-9_\-]*"
                    value={row.field}
                    onChange={(e) => update(row.key, { field: e.target.value })}
                  />
                </Field>
                <Field label="凭据值">
                  <ValueInput
                    name="value"
                    label={`字段 ${row.field || index + 1} 的值`}
                    value={row.value}
                    onChange={(value) => update(row.key, { value })}
                  />
                </Field>
                {rows.length === 1 ? null : (
                  <button
                    type="button"
                    className="btn btn--quiet"
                    onClick={() => setRows((list) => list.filter((r) => r.key !== row.key))}
                  >
                    移除
                  </button>
                )}
              </div>
            ))}
            <div className="form-actions">
              <button
                type="button"
                className="btn btn--ghost btn--small"
                onClick={() =>
                  setRows((list) => [
                    ...list,
                    { key: Math.max(0, ...list.map((r) => r.key)) + 1, field: '', value: '' },
                  ])
                }
              >
                <Icon name="plus" size={15} />
                增加字段
              </button>
              <FileButton label="从 JSON 文件填入" onFile={fill} />
            </div>
            <datalist id="secret-fields">
              {secret?.fields.map((name) => (
                <option key={name} value={name} />
              ))}
            </datalist>
            <p className="field-hint">
              {secret ? `现有字段：${secret.fields.join('、')}；填新字段名会新增该字段。` : ''}
              最多 20 个字段，字段名以字母或下划线开头。多行的值（如 PEM 私钥）直接粘贴、从文件读取或拖进值框；从 JSON
              文件填入会把每个字符串值填成一个字段，字段名取最内层的键名。
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
