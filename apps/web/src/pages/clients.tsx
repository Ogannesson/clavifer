import { useState } from 'react';
import { api, fv, lines, type Client } from '../api';
import { PageHead, RefreshButton, type AppApi } from '../shell';
import { Badge, Drawer, EmptyState, Field, Icon, Loading, Panel, useConfirm } from '../ui';

export function Clients({ app }: { app: AppApi }) {
  const [open, setOpen] = useState(false);
  const [created, setCreated] = useState<{ name: string; command: string } | null>(null);
  const confirm = useConfirm();
  const clients = [...app.status.clients].sort((a, b) => Number(!!a.disabled) - Number(!!b.disabled));

  const revoke = async (c: Client) => {
    const ok = await confirm({
      title: `撤销「${c.name}」`,
      body: '该实例的访问令牌与刷新令牌立即失效，它的全部资源授权同时被撤销，待审批的申请一并拒绝。已经发出的上游请求无法撤回。',
      confirmLabel: '撤销实例',
      danger: true,
    });
    if (!ok) return;
    await app.run(async () => {
      await api('/admin/clients/' + c.clientId, 'DELETE');
      await app.refresh();
    }, '安装实例已撤销。');
  };

  return (
    <>
      <PageHead
        title="安装实例"
        description="每台电脑或需要独立撤销的安装应使用不同实例。同一操作系统用户下的 Agent 仍共享系统凭据库访问能力。"
        actions={
          <>
            <RefreshButton app={app} />
            <button type="button" className="btn btn--ghost" onClick={() => location.assign('/device')}>
              <Icon name="device" size={16} />
              批准设备
            </button>
            <button type="button" className="btn" disabled={app.busy} onClick={() => setOpen(true)}>
              <Icon name="plus" size={16} />
              创建实例
            </button>
          </>
        }
      />
      {created ? (
        <Panel
          title={`「${created.name}」已创建`}
          description="在目标电脑上执行下面的内容完成登录。新实例还没有任何授权；授权按实例保存，之后用这个实例登录的设备都会拥有。"
          actions={
            <>
              <button
                type="button"
                className="btn btn--ghost btn--small"
                onClick={() =>
                  void navigator.clipboard.writeText(created.command).then(
                    () => app.notify('已复制。'),
                    () => app.notify('浏览器拒绝了复制，请手动选中上面的命令。', true),
                  )
                }
              >
                复制
              </button>
              <button type="button" className="btn btn--quiet" onClick={() => setCreated(null)}>
                知道了
              </button>
            </>
          }
        >
          <div className="panel-body">
            <pre>{created.command}</pre>
          </div>
        </Panel>
      ) : null}
      <Panel>
        {app.loading ? (
          <Loading />
        ) : clients.length ? (
          <div className="rows">
            {clients.map((c) => (
              <div className="row" key={c.clientId}>
                <div className="row-main">
                  <div className="row-title">
                    <h3>{c.name}</h3>
                    {c.disabled ? (
                      <Badge tone="danger">已撤销</Badge>
                    ) : c.userId ? (
                      <Badge tone="ok">可用</Badge>
                    ) : (
                      <Badge tone="warn">无归属，建议撤销</Badge>
                    )}
                  </div>
                  <p className="row-meta mono">{c.clientId}</p>
                  {c.userId ? null : (
                    <p className="row-meta">这条客户端记录没有 Owner 归属，即使走完设备流也无法访问 /v1。</p>
                  )}
                </div>
                {c.disabled ? null : (
                  <div className="row-actions">
                    <button
                      type="button"
                      className="btn btn--danger btn--small"
                      disabled={app.busy}
                      onClick={() => void revoke(c)}
                    >
                      撤销
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            title="还没有安装实例"
            description="创建实例后会给出 clavifer 登录命令；远程 MCP 客户端则填写回调地址，用 Client ID 走 OAuth。"
            action={
              <button type="button" className="btn" onClick={() => setOpen(true)}>
                创建实例
              </button>
            }
          />
        )}
      </Panel>

      <Drawer
        open={open}
        title="创建安装实例"
        description="本机 CLI 登录不需要回调地址。远程客户端需支持预先指定 client ID。"
        onClose={() => setOpen(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void app.run(async () => {
              const name = fv(f, 'name').trim();
              const redirectUris = lines(fv(f, 'redirectUris'));
              const c = await api('/admin/clients', 'POST', { name, redirectUris });
              setCreated({
                name,
                command: redirectUris.length
                  ? `MCP 地址：${location.origin}/v1/mcp\nClient ID：${String(c.clientId)}\n登录后仍需在“授权”页授予资源权限。`
                  : `clavifer login --server ${location.origin} --client-id ${String(c.clientId)}`,
              });
              setOpen(false);
              await app.refresh();
            }, '实例已创建，请按提示在电脑上登录。');
          }}
        >
          <Field label="实例名称" hint="写清设备与客户端，便于日后分别撤销。">
            <input name="name" maxLength={100} placeholder="我的电脑 · Codex" required />
          </Field>
          <Field label="回调地址（可选，每行一个）" hint="仅远程 MCP 客户端需要；本机 clavifer 登录请留空。">
            <textarea name="redirectUris" rows={3} placeholder="https://client.example.com/oauth/callback" />
          </Field>
          <div className="form-actions">
            <button className="btn" disabled={app.busy}>
              创建实例
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
