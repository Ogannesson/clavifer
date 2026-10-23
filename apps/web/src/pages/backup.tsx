import { useState } from 'react';
import {
  api,
  archiveErrorMessage,
  fault,
  fv,
  relativeText,
  startFullExport,
  timeText,
  type ExportStatus,
} from '../api';
import { PageHead, RefreshButton, auth, type AppApi } from '../shell';
import { Badge, Drawer, Field, Icon, Loading, Panel, useConfirm } from '../ui';

type Sheet = 'recipient' | 'full' | null;
type FullExport = {
  id: string;
  at: number;
  state: 'running' | 'complete' | 'failed' | 'unconfirmed';
  error?: string;
};
type Outcome = Pick<FullExport, 'state' | 'error'>;
// The data sealing never moves out stops every automatic backup on its own once it passes 9 MB; the page
// warns from 6 MB on, while there is still room to act.
const UNSEALED_WARNING = 6_000_000;
const unconfirmedText =
  '还没有收到服务端写完的确认，这份完整导出可能不完整，不要依赖它。很大的导出可能稍后才写完，可以再次检查；否则请删除已下载的文件，重新导出。';

/** Whether the server has recorded the full export with this id as written whole or as refused. */
async function exportOutcome(id: string): Promise<Outcome | null> {
  const { status, error } = (await api(`/admin/backup/exports/${id}`)) as ExportStatus;
  return status === 'complete' ? { state: 'complete' } : status === 'failed' ? { state: 'failed', error } : null;
}
/** Asks every 2 seconds, for up to 5 minutes. An export the CPU limit cut off records nothing more, so
 * only the deadline can tell it apart from one still running. */
async function watchExport(id: string): Promise<Outcome> {
  for (const deadline = Date.now() + 300_000; Date.now() < deadline;) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    // A status request that failed in passing says nothing about the export; the next one asks again.
    const outcome = await exportOutcome(id).catch(() => null);
    if (outcome) return outcome;
  }
  return { state: 'unconfirmed' };
}

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
  const [full, setFull] = useState<FullExport | null>(null);
  const confirm = useConfirm();
  const backup = app.status.backup;

  const exportAll = (recipient: string) =>
    app.run(async () => {
      // A link download cannot sign in again on its own, so the 10-minute rule is checked here first,
      // with a minute to spare; signing in again then runs this once more.
      const session = (await auth.getSession()).data?.session;
      if (!session || Date.now() - new Date(session.createdAt).getTime() > 540_000)
        throw fault('recent_login_required');
      const id = startFullExport(recipient);
      const at = Date.now();
      setSheet(null);
      setFull({ id, at, state: 'running' });
      void watchExport(id).then((outcome) => settle(id, at, outcome));
    }, '完整导出已开始下载，服务端写完后此页会确认。');
  const settle = (id: string, at: number, outcome: Outcome) => {
    setFull({ id, at, ...outcome });
    if (outcome.state === 'complete') app.notify('完整导出已全部写出。');
    else app.notify(outcome.state === 'failed' ? fault(outcome.error ?? '').message : unconfirmedText, true);
  };
  // After the deadline the Owner can still ask once more, for an export that took longer.
  const recheck = (f: FullExport) =>
    app.run(async () => settle(f.id, f.at, (await exportOutcome(f.id)) ?? { state: 'unconfirmed' }), '');

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
        description="服务端只保存加密文件和你的 age 公钥，私钥始终由你保管。自动备份与服务位于同一个 Cloudflare 账户，请定期下载完整导出，保存到账户之外。"
        actions={<RefreshButton app={app} />}
      />
      {app.loading || !backup ? (
        <Panel>
          <Loading />
        </Panel>
      ) : (
        <>
          {/* Until a backup succeeds again, a restore loses everything since the last one. */}
          {backup.lastError ? (
            <div className="alerts">
              <div className="alert alert--danger">
                <span className="alert-icon">
                  <Icon name="alert" size={18} />
                </span>
                <div className="alert-body">
                  <strong>
                    {backup.lastError === 'hot_data_over_limit' ? '热数据超限，自动备份已跳过' : '自动备份没有保存'}
                  </strong>
                  <p>
                    {fault(backup.lastError).message} 已保存的备份不受影响，但它之后的改动都还没有备份。上次成功：
                    {backup.lastSuccessAt ? timeText(backup.lastSuccessAt) : '尚未成功过'}。
                  </p>
                </div>
              </div>
            </div>
          ) : null}
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
                      <Badge>有改动待备份</Badge>
                    ) : backup.configured ? (
                      <Badge>已是最新</Badge>
                    ) : null}
                    {backup.lastError ? (
                      <Badge tone="danger">
                        {backup.lastError === 'hot_data_over_limit' ? '热数据超限' : '最近一次失败'}
                      </Badge>
                    ) : null}
                    {backup.retentionError ? <Badge tone="warn">旧副本清理失败</Badge> : null}
                    {backup.archiveError ? <Badge tone="warn">冷数据封存失败</Badge> : null}
                    {backup.unsealedBytes > UNSEALED_WARNING ? <Badge tone="warn">接近热数据上限</Badge> : null}
                  </div>
                  <p className="row-meta">
                    最近成功：
                    {backup.lastSuccessAt
                      ? `${timeText(backup.lastSuccessAt)}（${relativeText(backup.lastSuccessAt)}）`
                      : '尚未成功备份'}
                  </p>
                  <p className="row-meta">最近尝试：{timeText(backup.lastAttemptAt)}</p>
                  {backup.downloadAvailable ? (
                    <p className="row-meta">
                      下载的自动备份需与所在的桶一起使用：已封存的旧审计和访问申请只按键引用桶里的文件，不在备份之内。
                    </p>
                  ) : null}
                  {backup.retentionError ? (
                    <p className="row-meta">最新副本已保存成功，只是旧副本没能删除，下一次成功备份会重试清理。</p>
                  ) : null}
                  {backup.archiveError ? (
                    <p className="row-meta">封存失败原因：{archiveErrorMessage(backup.archiveError)}</p>
                  ) : null}
                  {backup.unsealedBytes > UNSEALED_WARNING ? (
                    <p className="row-meta">
                      凭据及其各版本、连接、安装实例、授权和管理员账户这些永不封存的数据已占{' '}
                      {(backup.unsealedBytes / 1_000_000).toFixed(1)} MB。超过 9 MB
                      后自动备份会一直跳过，只能靠完整导出；请删除不再使用的凭据和连接。
                    </p>
                  ) : null}
                </div>
                <div className="row-actions">
                  {backup.downloadAvailable ? (
                    <a className="btn btn--ghost btn--small" href="/admin/backup/latest" download>
                      <Icon name="download" size={15} />
                      下载最新的自动备份
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
            title="手动导出"
            description="完整导出包含实例的全部状态和已封存的冷数据，单独一个文件即可重建实例。失去这个 Cloudflare 账户时，能救回数据的只有保存在账户之外的完整导出，请定期下载一份。"
            actions={
              <button type="button" className="btn" disabled={app.busy} onClick={() => setSheet('full')}>
                完整导出
              </button>
            }
          >
            {full ? (
              <div className="rows">
                <div className="row">
                  <div className="row-main">
                    <div className="row-title">
                      <h3>完整导出</h3>
                      {full.state === 'running' ? (
                        <Badge tone="accent">正在导出</Badge>
                      ) : full.state === 'complete' ? (
                        <Badge tone="ok">已全部写出</Badge>
                      ) : full.state === 'failed' ? (
                        <Badge tone="danger">导出被拒绝</Badge>
                      ) : (
                        <Badge tone="danger">可能不完整</Badge>
                      )}
                    </div>
                    <p className="row-meta">开始于 {timeText(full.at)}</p>
                    <p className="row-meta">
                      {full.state === 'running'
                        ? '下载结束后，这里会显示服务端是否写完了最后一块。请不要关闭此页。'
                        : full.state === 'complete'
                          ? '服务端已写完最后一块。请把文件保存到 Cloudflare 账户之外的位置。'
                          : full.state === 'failed'
                            ? fault(full.error ?? '').message
                            : unconfirmedText}
                    </p>
                  </div>
                  {full.state === 'unconfirmed' ? (
                    <div className="row-actions">
                      <button
                        type="button"
                        className="btn btn--ghost btn--small"
                        disabled={app.busy}
                        onClick={() => void recheck(full)}
                      >
                        再次检查
                      </button>
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}
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
        open={sheet === 'full'}
        title="完整导出"
        description="需要 10 分钟内的登录。文件用你提供的 age 公钥加密，服务端不保留副本。"
        onClose={() => setSheet(null)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void exportAll(fv(new FormData(e.currentTarget), 'recipient').trim());
          }}
        >
          <Field label="age 公钥收件人" hint="默认是自动备份的公钥，也可以另用一个，包括以 age1pq1 开头的后量子公钥。">
            <input
              name="recipient"
              autoComplete="off"
              placeholder="age1…"
              required
              defaultValue={backup?.recipient ?? ''}
            />
          </Field>
          <p className="note">
            完整导出包含 Owner 的登录信息与 Passkey、全部凭据及其历史版本、API
            连接、安装实例、授权、访问申请和审计（含已封存的部分），单独一个文件即可重建整个实例，用于迁移和在
            Cloudflare 之外保存。自动备份只按键引用桶里已封存的部分，离开所在的桶就不完整，不能代替它。
          </p>
          <div className="form-actions">
            <button className="btn" disabled={app.busy}>
              开始导出
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
