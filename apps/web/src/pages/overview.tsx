import { fault, relativeText, timeText } from '../api';
import { PageHead, RefreshButton, type AppApi, type TabId } from '../shell';
import { Badge, Icon, Loading, Panel, type Tone } from '../ui';
import { isExpiringSoon, PendingCard } from './access';
import { runBackupNow } from './backup';
import { resultTone } from './audit';

type Action = { label: string; primary?: boolean; onClick: () => void };
type Item = {
  tone: Exclude<Tone, 'accent' | 'neutral'>;
  icon: string;
  title: string;
  body: string;
  actions?: Action[];
};

function backupItem(app: AppApi): Item {
  const backup = app.status.backup;
  const open = (label = '查看备份'): Action => ({ label, onClick: () => app.go('backup') });
  const runNow: Action = { label: '立即备份', primary: true, onClick: () => runBackupNow(app) };
  if (!backup?.configured)
    return {
      tone: 'warn',
      icon: 'archive',
      title: '自动备份未启用',
      body: '配置 age 公钥后，服务每 15 分钟检查变更并保存加密副本。没有备份时，删除凭据不可恢复。',
      actions: [open('去配置备份')],
    };
  if (backup.lastError)
    return {
      tone: 'danger',
      icon: 'alert',
      title: '最近一次自动备份失败',
      body: `${fault(backup.lastError).message} 上次成功：${backup.lastSuccessAt ? timeText(backup.lastSuccessAt) : '尚未成功过'}。`,
      actions: [open('查看原因'), runNow],
    };
  if (backup.retentionError)
    return {
      tone: 'warn',
      icon: 'archive',
      title: '旧副本清理失败',
      body: '最新备份已保存成功，只是旧副本没能删除。下一次成功备份会重试清理。',
      actions: [open('查看备份状态')],
    };
  if (backup.pending)
    return {
      tone: 'warn',
      icon: 'info',
      title: '有改动尚未备份',
      body: `凭据或连接在上次备份后发生过变化，计划任务会在 ${backup.scheduleMinutes} 分钟内保存新副本。`,
      actions: [runNow, open()],
    };
  return {
    tone: 'ok',
    icon: 'check',
    title: '自动备份正常',
    body: `最近成功备份：${timeText(backup.lastSuccessAt)}（${backup.lastSuccessAt ? relativeText(backup.lastSuccessAt) : '—'}）。请定期把副本下载到独立位置。`,
  };
}

export function Overview({ app }: { app: AppApi }) {
  const { secrets, connections, clients, grants, pending, events } = app.status;
  const active = clients.filter((c) => !c.disabled && c.userId);
  const orphans = clients.filter((c) => !c.disabled && !c.userId);
  const expiring = grants.filter(isExpiringSoon);

  const items: Item[] = [backupItem(app)];
  if (expiring.length)
    items.push({
      tone: 'warn',
      icon: 'grant',
      title: `${expiring.length} 项授权即将过期`,
      body: '到期后 Agent 会失去访问并重新申请。需要继续使用的资源可以提前重新授权。',
      actions: [{ label: '查看授权', onClick: () => app.go('access') }],
    });
  if (orphans.length)
    items.push({
      tone: 'danger',
      icon: 'device',
      title: `${orphans.length} 个无归属安装实例`,
      body: '这些客户端行没有 Owner 归属，访问 /v1 一律被拒，建议直接撤销。',
      actions: [{ label: '去处理', onClick: () => app.go('clients') }],
    });
  if (!active.length && !pending.length)
    items.push({
      tone: 'warn',
      icon: 'device',
      title: '还没有可用的安装实例',
      body: '先创建一个实例，再用它生成的登录命令在电脑上登录 clavifer。',
      actions: [{ label: '创建实例', onClick: () => app.go('clients') }],
    });

  const stats: { label: string; value: number; hint: string; tab: TabId }[] = [
    { label: '凭据', value: secrets.length, hint: '加密保存的项目', tab: 'secrets' },
    { label: 'API 连接', value: connections.length, hint: '受限的上游服务', tab: 'connections' },
    { label: '活跃实例', value: active.length, hint: '可独立撤销', tab: 'clients' },
    {
      label: '生效授权',
      value: grants.length,
      hint: expiring.length ? `${expiring.length} 项即将过期` : '按资源授予',
      tab: 'access',
    },
    { label: '待批准', value: pending.length, hint: pending.length ? '需要你的决定' : '没有待办', tab: 'access' },
  ];

  return (
    <>
      <PageHead
        title="需要关注的事"
        description="这里只显示需要判断或行动的状态，其余管理功能在导航分区中。"
        actions={<RefreshButton app={app} />}
      />
      {app.loading ? (
        <Panel>
          <Loading />
        </Panel>
      ) : (
        <>
          <div className="alerts">
            {pending.map((p) => (
              <PendingCard key={p.id} app={app} request={p} />
            ))}
            {items.map((item) => (
              <div className={`alert alert--${item.tone}`} key={item.title}>
                <span className="alert-icon">
                  <Icon name={item.icon} size={18} />
                </span>
                <div className="alert-body">
                  <strong>{item.title}</strong>
                  <p>{item.body}</p>
                  {item.actions ? (
                    <div className="alert-actions">
                      {item.actions.map((a) => (
                        <button
                          key={a.label}
                          type="button"
                          className={a.primary ? 'btn btn--small' : 'btn btn--ghost btn--small'}
                          disabled={app.busy}
                          onClick={a.onClick}
                        >
                          {a.label}
                        </button>
                      ))}
                    </div>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
          <div className="stats">
            {stats.map((s) => (
              <button type="button" className="stat" key={s.label} onClick={() => app.go(s.tab)}>
                <span className="stat-label">{s.label}</span>
                <strong>{s.value}</strong>
                <small>{s.hint}</small>
              </button>
            ))}
          </div>
          <Panel
            title="最近动作"
            description="审计记录的请求编号与响应头 x-request-id 一致。"
            actions={
              <button type="button" className="btn btn--quiet" onClick={() => app.go('audit')}>
                查看全部
              </button>
            }
          >
            <div className="rows">
              {events.slice(0, 5).map((e, i) => (
                <div className="row" key={`${e.request_id}-${i}`}>
                  <div className="row-main">
                    <div className="row-title">
                      <h3>{e.action}</h3>
                      <Badge tone={resultTone(e.result)}>{e.result}</Badge>
                    </div>
                    <p className="row-meta">{timeText(e.created_at)}</p>
                  </div>
                  <span className="mono">{String(e.request_id ?? '').slice(0, 8)}</span>
                </div>
              ))}
              {events.length ? null : <div className="empty">暂无记录。</div>}
            </div>
          </Panel>
        </>
      )}
    </>
  );
}
