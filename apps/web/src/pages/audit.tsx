import { clientName, resourceName, timeText } from '../api';
import { PageHead, RefreshButton, type AppApi } from '../shell';
import { Badge, EmptyState, Loading, Panel, type Tone } from '../ui';

export const resultTone = (result: string): Tone => {
  if (result === 'ok' || result === 'authorized' || /^http_[23]/.test(result)) return 'ok';
  if (result === 'started') return 'neutral';
  return 'danger';
};

export function Audit({ app }: { app: AppApi }) {
  const { events } = app.status;
  return (
    <>
      <PageHead
        title="审计"
        description="最近 50 条管理与调用记录。每行的请求编号与当时响应头的 x-request-id 相同，可用于对照服务日志。"
        actions={<RefreshButton app={app} />}
      />
      <Panel>
        {app.loading ? (
          <Loading />
        ) : events.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>动作</th>
                  <th>来源</th>
                  <th>资源</th>
                  <th>结果</th>
                  <th>请求编号</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => (
                  <tr key={`${e.request_id}-${i}`}>
                    <td>{timeText(e.created_at)}</td>
                    <td>{e.action}</td>
                    <td>
                      {e.client_id === 'owner' || e.client_id === 'system'
                        ? e.client_id
                        : clientName(app.status, String(e.client_id))}
                    </td>
                    <td className="wrap">{e.resource_id ? resourceName(app.status, e.resource_id) : '—'}</td>
                    <td>
                      <Badge tone={resultTone(e.result)}>{e.result}</Badge>
                    </td>
                    <td className="mono">{String(e.request_id ?? '').slice(0, 8)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="暂无记录" description="管理操作与 Agent 调用都会写入审计，日志不收集请求内容。" />
        )}
      </Panel>
    </>
  );
}
