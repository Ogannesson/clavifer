import type { ReactNode } from 'react';
import { createAuthClient } from 'better-auth/client';
import { passkeyClient } from '@better-auth/passkey/client';
import { send, type Status } from './api';
import { Icon } from './ui';

/** Shared by the console and the entry pages, so neither has to import the other's module. */
export const auth = createAuthClient({
  baseURL: location.origin,
  plugins: [passkeyClient()],
  fetchOptions: { customFetchImpl: send },
});
export type Owner = { name: string; email: string } | null;

export const TABS = [
  { id: 'overview', label: '概览', icon: 'gauge' },
  { id: 'secrets', label: '凭据', icon: 'key' },
  { id: 'connections', label: 'API 连接', icon: 'link' },
  { id: 'clients', label: '安装实例', icon: 'device' },
  { id: 'access', label: '授权', icon: 'grant' },
  { id: 'backup', label: '备份', icon: 'archive' },
  { id: 'audit', label: '审计', icon: 'ledger' },
  { id: 'account', label: '账户', icon: 'user' },
] as const;
export type TabId = (typeof TABS)[number]['id'];

export type AppApi = {
  status: Status;
  loading: boolean;
  busy: boolean;
  owner: Owner;
  /** Resolves with the state just loaded, so a caller can report what the server actually kept. */
  refresh: () => Promise<Status | null>;
  run: (fn: () => Promise<void>, success?: string) => Promise<void>;
  go: (tab: TabId) => void;
  notify: (text: string, error?: boolean) => void;
  signOut: () => Promise<void>;
};

/** Every page opens with the same title block, so the console reads consistently. */
export function PageHead({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {description ? <p>{description}</p> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function RefreshButton({ app }: { app: AppApi }) {
  return (
    <button
      type="button"
      className="btn btn--ghost"
      disabled={app.busy}
      onClick={() =>
        void app.run(async () => {
          await app.refresh();
        }, '')
      }
    >
      <Icon name="refresh" size={16} />
      刷新
    </button>
  );
}
