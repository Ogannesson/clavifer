import { useEffect, useState } from 'react';
import type { Passkey } from '@better-auth/passkey/client';
import { authFault, fv, timeText } from '../api';
import { auth, PageHead, type AppApi } from '../shell';
import { Badge, Drawer, EmptyState, Field, Icon, Loading, Panel, useConfirm } from '../ui';

export function Account({ app }: { app: AppApi }) {
  const [open, setOpen] = useState(false);
  // 'failed' replaces a list that could not be loaded, so the page never shows a stale or endless one.
  const [passkeys, setPasskeys] = useState<Passkey[] | 'failed' | null>(null);
  // 'new' registers an authenticator; a Passkey renames that one.
  const [editing, setEditing] = useState<Passkey | 'new' | null>(null);
  const confirm = useConfirm();

  const loadPasskeys = async () => {
    try {
      const r = await auth.passkey.listUserPasskeys();
      if (r.error) throw authFault(r.error);
      setPasskeys(r.data);
    } catch (e) {
      // A dropped connection throws instead of returning an error, so both end here.
      setPasskeys('failed');
      throw e;
    }
  };
  /** After a change that already succeeded, a failed reload must not read as a failed change. */
  const reloadAfter = (done: string) =>
    loadPasskeys().catch(() => {
      throw new Error(`${done}，但列表刷新失败，请点“重试”。`);
    });
  useEffect(() => {
    void app.run(loadPasskeys, '');
    // Loaded once on entry; every change below reloads it explicitly.
  }, []);

  const remove = async (p: Passkey) => {
    const ok = await confirm({
      title: `删除「${p.name || 'Passkey'}」`,
      body: '删除后这个认证器不能再登录本服务，密码登录仍然可用。认证器里残留的条目可以在设备上自行清除。',
      confirmLabel: '删除 Passkey',
      danger: true,
    });
    if (!ok) return;
    await app.run(async () => {
      const r = await auth.passkey.deletePasskey({ id: p.id });
      if (r.error) throw authFault(r.error);
      await reloadAfter('Passkey 已删除');
    }, 'Passkey 已删除。');
  };

  return (
    <>
      <PageHead
        title="账户"
        description="管理网页只有 Passkey 和账号密码两种入口。请至少保留一条可用路径：没有邮件找回。"
      />
      <Panel title="管理员">
        <div className="rows">
          <div className="row">
            <div className="row-main">
              <div className="row-title">
                <h3>{app.owner?.name}</h3>
              </div>
              <p className="row-meta mono">{app.owner?.email}</p>
              <p className="row-meta">网页会话有效期 24 小时，活动中会滑动续期；敏感操作要求 10 分钟内的登录。</p>
            </div>
            <div className="row-actions">
              <button
                type="button"
                className="btn btn--ghost btn--small"
                disabled={app.busy}
                onClick={() =>
                  void (async () => {
                    const ok = await confirm({
                      title: '退出网页登录',
                      body: '已授权的安装实例不受影响，可随时重新登录。',
                      confirmLabel: '退出',
                    });
                    if (ok) await app.run(app.signOut, '');
                  })()
                }
              >
                退出网页
              </button>
            </div>
          </div>
        </div>
      </Panel>
      <Panel
        title="Passkey"
        description="可登记多个认证器并保留备用登录方式；登记、改名和删除需要 10 分钟内的登录。"
        actions={
          <button type="button" className="btn" disabled={app.busy} onClick={() => setEditing('new')}>
            <Icon name="shield" size={16} />
            登记新的 Passkey
          </button>
        }
      >
        {passkeys === null ? (
          <Loading />
        ) : passkeys === 'failed' ? (
          <EmptyState
            title="Passkey 列表加载失败"
            description="可能是网络中断或登录已失效。重试仍失败时，请刷新页面或重新登录。"
            action={
              <button type="button" className="btn" disabled={app.busy} onClick={() => void app.run(loadPasskeys, '')}>
                重试
              </button>
            }
          />
        ) : passkeys.length ? (
          <div className="rows">
            {passkeys.map((p) => (
              <div className="row" key={p.id}>
                <div className="row-main">
                  <div className="row-title">
                    <h3>{p.name || '未命名 Passkey'}</h3>
                    {p.backedUp ? <Badge>已同步</Badge> : null}
                  </div>
                  <p className="row-meta">登记于 {timeText(new Date(p.createdAt).getTime())}</p>
                </div>
                <div className="row-actions">
                  <button
                    type="button"
                    className="btn btn--ghost btn--small"
                    disabled={app.busy}
                    onClick={() => setEditing(p)}
                  >
                    改名
                  </button>
                  <button
                    type="button"
                    className="btn btn--danger btn--small"
                    disabled={app.busy}
                    onClick={() => void remove(p)}
                  >
                    删除
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            title="还没有登记 Passkey"
            description="目前只能用密码登录。登记一个 Passkey 后，日常登录无需输入密码。"
          />
        )}
      </Panel>
      <Panel
        title="密码"
        description="修改后会退出网页登录并撤销其他会话，已授权的 Agent 由实例与资源授权单独管理。"
        actions={
          <button type="button" className="btn btn--ghost" disabled={app.busy} onClick={() => setOpen(true)}>
            修改密码
          </button>
        }
      >
        <div className="panel-body">
          <p className="note">
            密码至少 12 位。失去所有登录方式时，由部署这个服务的操作者签发找回令牌，在 /setup
            页面设置新密码；这会删除全部 Passkey 和会话，安装实例和授权保留。
          </p>
        </div>
      </Panel>

      <Drawer
        open={editing !== null}
        title={editing === 'new' ? '登记新的 Passkey' : '修改 Passkey 名称'}
        description={editing === 'new' ? '保存后浏览器会请你用认证器确认。名称只用于在此列表中区分设备。' : undefined}
        onClose={() => setEditing(null)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const name = fv(new FormData(e.currentTarget), 'name').trim();
            const target = editing;
            if (!target) return;
            void app.run(
              async () => {
                const r =
                  target === 'new'
                    ? await auth.passkey.addPasskey({ name })
                    : await auth.passkey.updatePasskey({ id: target.id, name });
                if (r.error) throw authFault(r.error);
                setEditing(null);
                await reloadAfter(target === 'new' ? '已登记新的 Passkey' : 'Passkey 名称已修改');
              },
              target === 'new' ? '已登记新的 Passkey。' : 'Passkey 名称已修改。',
            );
          }}
        >
          <Field label="名称" hint="写清设备或认证器，便于日后分别删除。">
            <input
              name="name"
              maxLength={100}
              required
              defaultValue={
                editing === 'new' ? `Passkey ${new Date().toLocaleDateString('zh-CN')}` : (editing?.name ?? '')
              }
            />
          </Field>
          <div className="form-actions">
            <button className="btn" disabled={app.busy}>
              {editing === 'new' ? '登记' : '保存'}
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => setEditing(null)}>
              取消
            </button>
          </div>
        </form>
      </Drawer>
      <Drawer
        open={open}
        title="修改管理员密码"
        description="保存后会立即退出网页，请使用新密码重新登录。"
        onClose={() => setOpen(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void app.run(async () => {
              if (fv(f, 'newPassword') !== fv(f, 'confirmPassword')) throw new Error('两次输入的新密码不一致。');
              const r = await auth.changePassword({
                currentPassword: fv(f, 'currentPassword'),
                newPassword: fv(f, 'newPassword'),
                revokeOtherSessions: true,
              });
              if (r.error) throw authFault(r.error);
              setOpen(false);
              // The password is already changed; a failed sign-out must not read as a failed change.
              await app.signOut().catch(() => {
                throw new Error('密码已修改，但退出登录失败，请手动退出后用新密码登录。');
              });
            }, '密码已修改，请使用新密码重新登录。');
          }}
        >
          <Field label="当前密码">
            <input name="currentPassword" type="password" autoComplete="current-password" required />
          </Field>
          <Field label="新密码">
            <input
              name="newPassword"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={128}
              required
            />
          </Field>
          <Field label="再次输入新密码">
            <input
              name="confirmPassword"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={128}
              required
            />
          </Field>
          <div className="form-actions">
            <button className="btn" disabled={app.busy}>
              修改密码并退出
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
