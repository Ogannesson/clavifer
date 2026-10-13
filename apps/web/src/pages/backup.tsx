import { useState } from 'react';
import { api, downloadExport, fault, fv, relativeText, timeText } from '../api';
import { PageHead, RefreshButton, type AppApi } from '../shell';
import { Badge, Drawer, Field, Icon, Loading, Panel, useConfirm } from '../ui';

type Sheet = 'recipient' | 'export' | 'restore' | null;

/** /admin/backup/run answers 200 with an outcome, so a no-op must not be reported as a new copy. */
export const runBackupNow = (app: AppApi) =>
  void app.run(async () => {
    const result = await api('/admin/backup/run', 'POST');
    if (result.outcome === 'not_configured') throw new Error('请先填写 age 公钥并保存自动备份设置。');
    if (result.outcome === 'running') throw new Error('已有备份正在运行，请稍后刷新查看结果。');
    if (result.outcome === 'superseded') throw new Error('备份期间设置发生变化，请刷新后重试。');
    if (result.outcome === 'up_to_date') throw new Error('没有新的改动需要备份。');
    await app.refresh();
  }, '加密备份已保存。');

export function Backup({ app }: { app: AppApi }) {
  const [sheet, setSheet] = useState<Sheet>(null);
  const confirm = useConfirm();
  const backup = app.status.backup;

  const disable = async () => {
    const ok = await confirm({
      title: '暂停自动备份',
      body: '服务将不再保存新的加密副本，已保存的副本仍然保留。凭据变更后不会有新的可恢复点。',
      confirmLabel: '暂停自动备份',
      danger: true,
    });
    if (!ok) return;
    await app.run(async () => {
      await api('/admin/backup/config', 'PUT', { recipient: null });
      await app.refresh();
    }, '自动备份已暂停，已保存的备份仍保留。');
  };

  return (
    <>
      <PageHead
        title="备份"
        description="服务端只保存加密文件和你的 age 公钥，私钥始终由你保管。R2 副本与服务位于同一账户，请定期下载到独立位置。"
        actions={<RefreshButton app={app} />}
      />
      {app.loading || !backup ? (
        <Panel>
          <Loading />
        </Panel>
      ) : (
        <>
          <Panel
            title="自动备份"
            description={`每 ${backup.scheduleMinutes} 分钟检查变更，无变更时每天保存一份。`}
            actions={
              <>
                <button
                  type="button"
                  className="btn btn--ghost"
                  disabled={app.busy}
                  onClick={() => setSheet('recipient')}
                >
                  {backup.configured ? '更改收件人' : '配置收件人'}
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={app.busy || !backup.configured}
                  onClick={() => runBackupNow(app)}
                >
                  立即备份
                </button>
              </>
            }
          >
            <div className="rows">
              <div className="row">
                <div className="row-main">
                  <div className="row-title">
                    <h3>状态</h3>
                    {backup.configured ? <Badge tone="ok">已启用</Badge> : <Badge tone="warn">未启用</Badge>}
                    {backup.running ? (
                      <Badge tone="accent">正在备份</Badge>
                    ) : backup.pending ? (
                      <Badge tone="warn">有改动待备份</Badge>
                    ) : backup.configured ? (
                      <Badge>已是最新</Badge>
                    ) : null}
                    {backup.lastError ? <Badge tone="danger">最近一次失败</Badge> : null}
                    {backup.retentionError ? <Badge tone="warn">旧副本清理失败</Badge> : null}
                  </div>
                  <p className="row-meta">
                    最近成功：
                    {backup.lastSuccessAt
                      ? `${timeText(backup.lastSuccessAt)}（${relativeText(backup.lastSuccessAt)}）`
                      : '尚未成功备份'}
                  </p>
                  <p className="row-meta">最近尝试：{timeText(backup.lastAttemptAt)}</p>
                  {backup.lastError ? <p className="row-meta">失败原因：{fault(backup.lastError).message}</p> : null}
                  {backup.retentionError ? (
                    <p className="row-meta">最新副本已保存成功，只是旧副本没能删除，下一次成功备份会重试清理。</p>
                  ) : null}
                </div>
                <div className="row-actions">
                  {backup.downloadAvailable ? (
                    <a className="btn btn--ghost btn--small" href="/admin/backup/latest" download>
                      <Icon name="download" size={15} />
                      下载最近副本
                    </a>
                  ) : null}
                  {backup.configured ? (
                    <button
                      type="button"
                      className="btn btn--danger btn--small"
                      disabled={app.busy}
                      onClick={() => void disable()}
                    >
                      暂停
                    </button>
                  ) : null}
                </div>
              </div>
              <div className="row">
                <div className="row-main">
                  <div className="row-title">
                    <h3>收件人与保留</h3>
                  </div>
                  <p className="row-meta mono">{backup.recipient ?? '未设置 age 公钥收件人'}</p>
                  <p className="row-meta">
                    备份成功后清理旧副本：最近 {backup.retention.daily} 天每天保留最新一份，此前{' '}
                    {backup.retention.monthly} 个月每月保留最新一份，当前可下载的副本始终保留。
                  </p>
                </div>
              </div>
            </div>
          </Panel>
          <Panel
            title="手动导出与恢复"
            description="导出的内容是当前有效凭据与连接，不包含历史版本、登录令牌与授权。"
            actions={
              <>
                <button type="button" className="btn btn--ghost" disabled={app.busy} onClick={() => setSheet('export')}>
                  下载加密备份
                </button>
                <button
                  type="button"
                  className="btn btn--ghost"
                  disabled={app.busy}
                  onClick={() => setSheet('restore')}
                >
                  从备份恢复
                </button>
              </>
            }
          >
            <div className="panel-body">
              <p className="note">
                恢复只能在全新的空凭据库中进行：先初始化新 Owner，不创建任何实例、凭据或连接，再在此处选择 .age
                文件和对应私钥。浏览器先解密，再通过同源连接写入新库并以新库密钥重新加密。恢复后需要重新登录、创建实例并重新授权。
              </p>
            </div>
          </Panel>
        </>
      )}

      <Drawer
        open={sheet === 'recipient'}
        title="自动备份收件人"
        description="需要 10 分钟内的登录。替换公钥后，旧备份仍需要旧私钥解密。"
        onClose={() => setSheet(null)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void app.run(async () => {
              await api('/admin/backup/config', 'PUT', { recipient: fv(f, 'recipient').trim() });
              const result = await api('/admin/backup/run', 'POST');
              setSheet(null);
              await app.refresh();
              if (result.outcome !== 'saved') throw new Error('设置已保存，但首次备份没有完成，请稍后在此页重试。');
            }, '设置已保存，并已完成一次备份。');
          }}
        >
          <Field label="age 公钥收件人" hint="以 age1 开头的公钥。私钥请自行保管，不要填写到这里。">
            <input
              name="recipient"
              autoComplete="off"
              placeholder="age1…"
              required
              defaultValue={backup?.recipient ?? ''}
            />
          </Field>
          <div className="form-actions">
            <button className="btn" disabled={app.busy}>
              保存并立即备份
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => setSheet(null)}>
              取消
            </button>
          </div>
        </form>
      </Drawer>

      <Drawer
        open={sheet === 'export'}
        title="下载加密备份"
        description="需要 10 分钟内的登录。文件用你提供的 age 公钥加密，服务端不保留副本。"
        onClose={() => setSheet(null)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void app.run(async () => {
              await downloadExport(fv(f, 'recipient').trim());
              setSheet(null);
            }, '加密备份已开始下载。');
          }}
        >
          <Field label="age 公钥收件人" hint="可以与自动备份使用同一个公钥，也可以另用一个。">
            <input name="recipient" autoComplete="off" placeholder="age1…" required />
          </Field>
          <div className="form-actions">
            <button className="btn" disabled={app.busy}>
              下载加密备份
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => setSheet(null)}>
              取消
            </button>
          </div>
        </form>
      </Drawer>

      <Drawer
        open={sheet === 'restore'}
        title="从备份恢复"
        description="需要 10 分钟内的登录，且目标必须是空凭据库。私钥只在当前浏览器中用于解密。"
        onClose={() => setSheet(null)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void (async () => {
              const file = f.get('file') as File;
              if (file.size > 10 * 1024 * 1024) {
                app.notify('备份超过 10 MiB 限制。', true);
                return;
              }
              const ok = await confirm({
                title: '恢复到当前凭据库',
                body: '恢复会把备份中的凭据与连接写入这个库，登录、实例与授权不会一并恢复。只能在空库中进行。',
                confirmLabel: '解密并恢复',
                danger: true,
              });
              if (!ok) return;
              await app.run(async () => {
                // The decrypter is a separate chunk; failing to load it is a connection problem, not a bad key.
                const { Decrypter } = await import('age-encryption').catch(() => {
                  throw fault('network_error');
                });
                let snapshot: unknown;
                // age reports a wrong key, a wrong file or a damaged file in English; all mean the same to the Owner.
                try {
                  const d = new Decrypter();
                  d.addIdentity(fv(f, 'identity').trim());
                  snapshot = JSON.parse(await d.decrypt(new Uint8Array(await file.arrayBuffer()), 'text'));
                } catch {
                  throw fault('backup_decrypt_failed');
                }
                await api('/admin/backup/restore', 'POST', snapshot);
                setSheet(null);
                await app.refresh();
              }, '恢复完成，请重新创建实例并授权。');
            })();
          }}
        >
          <Field label="备份文件">
            <input name="file" type="file" accept=".age" required />
          </Field>
          <Field label="age 私钥" hint="以 AGE-SECRET-KEY-1 开头，只在浏览器内使用。">
            <input name="identity" type="password" autoComplete="off" required />
          </Field>
          <div className="form-actions">
            <button className="btn btn--danger" disabled={app.busy}>
              解密并恢复
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => setSheet(null)}>
              取消
            </button>
          </div>
        </form>
      </Drawer>
    </>
  );
}
