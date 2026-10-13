// Every management call goes through here so error codes reach the user as one consistent sentence.
export type Secret = {
  id: string;
  name: string;
  description: string;
  current_version: number;
  updated_at: number;
  fields: string[];
};
export type ConnectionAuth =
  | { type: 'none' }
  | { type: 'bearer'; secretId: string; field: string }
  | { type: 'header'; secretId: string; field: string; name: string }
  | { type: 'basic'; secretId: string; usernameField: string; passwordField: string }
  | { type: 'query'; secretId: string; field: string; name: string };
export type Connection = {
  id: string;
  name: string;
  origin: string;
  description: string;
  auth_json: string;
  policy_json: string;
  updated_at: number;
};
export type ConnectionPolicy = {
  paths: string[];
  methods?: string[];
  deny?: string[];
  approval?: string[];
  free?: string[];
  /** Extra hosts a one-time approval may send a request to, each a hostname or "*.suffix"; anyHost
   * lets one go to any public HTTPS origin. A stored policy that has neither allows no other host. */
  hosts?: string[];
  anyHost?: boolean;
};
export type Client = { clientId: string; name: string; disabled: number | boolean; userId: string | null };
export type Grant = {
  id: string;
  client_id: string;
  resource_type: 'secret' | 'connection';
  resource_id: string;
  permission: string;
  fields: string[] | null;
  /** Temporary scope extensions of a connection grant, each with its own expiry. */
  extensions: { paths: string[]; methods: string[]; expiresAt: number | null }[];
  expires_at: number | null;
};
export type RequestedGrant = {
  resourceId: string;
  permission: string;
  fields?: string[];
  paths?: string[];
  methods?: string[];
};
/** One exact request an Agent asks the Owner to let run once; origin when it goes to another origin
 * than the connection's own, as the server normalized it. */
export type Invocation = {
  connection: string;
  origin?: string;
  method: string;
  path: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: string;
};
/** A request an Agent's draft policy was tested with; expect is run or a refusal code. */
export type PolicyTest = { method: string; path: string; grant: boolean; expect: string };
export type DraftPolicy = Required<Omit<ConnectionPolicy, 'hosts' | 'anyHost'>>;
// Each auth type on its own, so the type narrows after dropping secretId.
type WithoutSecretId<A> = A extends unknown ? Omit<A, 'secretId'> : never;
/** How a connection injects its credential, without which credential: a draft names none yet. */
export type DraftAuth = WithoutSecretId<ConnectionAuth>;
/** A credential (field names only) and the connections using it that an Agent proposes, each with its
 * own tests; the Owner enters the values. */
export type Setup = {
  secret?: { name: string; description: string; fields: string[] };
  connections: (DraftPolicy & {
    name: string;
    origin: string;
    description: string;
    hosts?: string[];
    auth: DraftAuth;
    tests: PolicyTest[];
  })[];
};
/** Changes an Agent proposes to a connection's name, notes, scope and rules; never its origin or auth. */
export type Update = {
  connection: string;
  changes: Partial<DraftPolicy & { name: string; description: string }>;
  tests: PolicyTest[];
};
export type Pending = {
  id: string;
  client_id: string;
  requested_json: string;
  reason: string;
  expires_at: number;
  /** For an invocation to another origin than its connection's own, where that origin stands under the
   * connection as it is now: the extra host covering it, if any, and whether the connection reaches any
   * host. The server works it out; hostname is as URL writes it (punycode). */
  elsewhere?: { hostname: string; host: string | null; anyHost: boolean };
};
export type AuditEvent = {
  action: string;
  client_id: string | null;
  resource_id: string | null;
  result: string;
  request_id: string;
  created_at: number;
};
export type BackupStatus = {
  configured: boolean;
  recipient: string | null;
  revision: number;
  savedRevision: number;
  lastSuccessAt: number | null;
  lastAttemptAt: number | null;
  lastError: string | null;
  retentionError: string | null;
  pending: boolean;
  running: boolean;
  downloadAvailable: boolean;
  scheduleMinutes: number;
  retention: { daily: number; monthly: number };
};
export type Status = {
  backup?: BackupStatus;
  secrets: Secret[];
  connections: Connection[];
  clients: Client[];
  grants: Grant[];
  pending: Pending[];
  events: AuditEvent[];
};
export const emptyStatus = (): Status => ({
  secrets: [],
  connections: [],
  clients: [],
  grants: [],
  pending: [],
  events: [],
});

const errorText: Record<string, string> = {
  recent_login_required: '这项操作需要 10 分钟内的登录，请重新登录后重试。',
  request_failed: '服务返回了无法识别的响应，请稍后重试或查看服务日志。',
  owner_auth_required: '请先登录管理员账户。',
  origin_not_allowed: '请求来源不受信任，请从本站重新打开页面。',
  invalid_bootstrap_token: '初始化令牌不正确。',
  bootstrap_already_used: '本服务已经创建过管理员，请直接登录。',
  bootstrap_in_progress: '另一处正在初始化管理员，请稍后刷新。',
  version_conflict: '此凭据已被更新，请刷新后重新轮换。',
  insufficient_scope: '当前没有这项资源的使用权限。',
  existing_grant_conflict: '该资源已有字段范围不同的有效授权。请先在授权表单手工调整该授权，再批准或拒绝此申请。',
  restore_requires_empty_vault: '恢复只能在空凭据库中进行。',
  use_path_prefix_not_glob: '路径请输入 /v1 这样的前缀，不使用星号。',
  invalid_rule:
    '格式不正确：每行写「方法 路径」或只写路径，方法为 GET、POST 等或 *，路径以 / 开头，不含 ; 和控制字符，只能在末尾写 /* 表示含子路径，例如 DELETE /v1/items/*。',
  too_many_rules: '超过 50 条上限，请合并为带 /* 的前缀规则。',
  invalid_host:
    '写法不正确：每行一个小写域名（如 artifacts.example.com）或 *.后缀（如 *.example.com，* 后至少两段），不带 https://、端口和路径，不能是 IP 或本地域名；中文等域名写成 xn-- 形式。',
  public_origin_required: '连接地址必须是管理员信任的公网域名。',
  origin_must_be_https: '连接地址必须是 https:// 开头的公网域名。',
  invalid_path:
    '路径前缀格式不正确，应形如 /v1：不含空格、查询串、; 和控制字符，也不含空段、. 或 .. 段（百分号编码后同样不行；段内的 %2F、%20 可以）。',
  invalid_input: '填写的内容不符合要求，请检查各字段后重试。',
  secret_in_use: '此凭据仍被 API 连接使用，请先删除或修改对应连接。',
  secret_not_found: '找不到这项凭据，可能已被删除，请刷新后重试。',
  secret_field_not_found: '绑定的字段在该凭据中不存在，请先轮换凭据补上这个字段。',
  invalid_header_credential: '用于请求头的凭据值必须是首尾无空格的可打印 ASCII。',
  invalid_basic_credential: 'Basic 的用户名不能包含冒号，用户名和密码都不能包含控制字符。',
  connection_or_binding_not_found: '找不到这条连接或它绑定的凭据，请刷新后重试。',
  client_not_found: '找不到这个安装实例，可能已被撤销。',
  resource_not_found: '被授权的资源已不存在，请刷新后重试。',
  request_not_found: '这条申请已过期或已被处理。',
  connection_changed: '这条连接在 Agent 提交修改后又被改过或已删除，草案只能拒绝；Agent 可以按现状重新提交。',
  secret_fields_mismatch: '填写的字段与草案不一致，请刷新页面后重试。',
  origin_mismatch: '页面已过期或地址不一致，请刷新后重试。',
  secret_name_taken:
    '凭据名称已被占用（已删除的凭据也占着名称），这份草案无法批准。请拒绝它，让 Agent 换个名字重新提交。',
  duplicate_secret: '已存在同名凭据，请换一个名称。',
  conflict: '存在同名或重复的记录，请换一个名称。',
  endpoint_disabled: '此接口在本服务中已关闭。',
  body_too_large: '提交的内容超出大小限制。',
  headers_too_large: '请求头总量超出大小限制。',
  invalid_backup_recipient: 'age 公钥格式不正确。请填写公钥接收者，不能填写私钥。',
  backup_not_found: '还没有可下载的备份。',
  backup_failed: '备份暂未成功，稍后会重试；请保留已有备份。',
  backup_has_broken_connection: '存在失效的凭据绑定，请修复或删除对应 API 连接后再备份。',
  backup_limit_exceeded: '凭据或连接数量超出单次备份上限（各 500 条 / 8 MiB）。',
  backup_storage_failed: '加密副本写入存储失败，请稍后重试。',
  backup_state_unavailable: '备份状态暂时不可读，请稍后重试。',
  backup_decrypt_failed: '无法解密：请确认选择的是 .age 备份文件，并填写与之对应的 age 私钥。',
  internal_error: '操作失败。请查看服务日志中的请求编号。',
  too_many_requests: '操作过于频繁，请稍后再试。',
  network_error: '无法连接服务，请检查网络后重试。',
  // Better Auth and its plugins: login, password change, Passkey, device approval and OAuth consent.
  INVALID_EMAIL_OR_PASSWORD: '邮箱或密码不正确。',
  INVALID_PASSWORD: '当前密码不正确。',
  PASSWORD_TOO_SHORT: '新密码至少需要 12 位。',
  PASSWORD_TOO_LONG: '新密码不能超过 128 位。',
  UNAUTHORIZED: '登录已失效，请重新登录后再试。',
  SESSION_NOT_FRESH: '这项操作需要最近的登录，请重新登录后再试。',
  CHALLENGE_NOT_FOUND: 'Passkey 验证已过期，请重新操作。',
  AUTH_CANCELLED: 'Passkey 操作已取消或超时。',
  ERROR_CEREMONY_ABORTED: 'Passkey 操作已取消或超时。',
  ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY: 'Passkey 操作已取消或超时。',
  ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED: '这个认证器已经登记过。',
  AUTHENTICATION_FAILED: 'Passkey 验证失败，请使用已登记的认证器或改用密码登录。',
  PASSKEY_NOT_FOUND: '找不到这个 Passkey，它可能已被删除或未在本服务登记。请刷新列表，登录时可改用其他认证器或密码。',
  invalid_request: '请求无效或已处理：请核对设备短码，或回到客户端重新发起登录。',
  expired_token: '设备短码已过期，请在客户端重新发起登录。',
  invalid_signature: '登录请求已过期，请回到客户端重新发起。',
};

export class Fault extends Error {
  code: string;
  constructor(code: string, text: string) {
    super(text);
    this.code = code;
  }
}
// Upstream English messages are never shown; an unmapped code still names itself for troubleshooting.
export const fault = (code: string) => new Fault(code, errorText[code] ?? `操作失败（${code}）。`);
// Better Auth answers a rate limit with a bare 429 that carries no code.
const failure = (status: number, code: unknown) =>
  fault(String(code ?? (status === 429 ? 'too_many_requests' : 'request_failed')));
/** The Better Auth client returns its errors instead of throwing them. Better Auth names the code
 * `code`; the Worker's own guards in front of it (owner, recent login, origin) answer with `error`. */
export const authFault = (e: { code?: string; error?: string; status: number }) => failure(e.status, e.code ?? e.error);

/** Every request goes through here, the Better Auth client included: fetch only rejects when no
 * response arrived at all, and then reports it in English. */
export const send = (input: RequestInfo | URL, init?: RequestInit) =>
  fetch(input, init).catch(() => {
    throw fault('network_error');
  });

export async function api(path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) {
  const r = await send(path, {
    method,
    credentials: 'same-origin',
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = r.headers.get('content-type')?.split(';')[0] === 'application/json';
  const value = json ? ((await r.json()) as Record<string, unknown>) : {};
  if (!r.ok || !json) {
    const e = failure(r.status, value.error ?? value.code);
    // A rule error names its list and line ("deny line 3"); say which one the Owner has to fix.
    const at = String(value.hint ?? '').match(/^(deny|approval|free)(?: line (\d+))?$/);
    if (at && ['invalid_rule', 'too_many_rules'].includes(e.code))
      e.message = `「${ruleKindText[at[1]]}」规则${at[2] ? `第 ${at[2]} 条` : ''}${e.message}`;
    const host = String(value.hint ?? '').match(/^hosts line (\d+)$/);
    if (host && e.code === 'invalid_host') e.message = `「额外域名」第 ${host[1]} 条${e.message}`;
    throw e;
  }
  return value;
}
export const ruleKindText: Record<string, string> = { deny: '拒绝', approval: '必须单次审批', free: '免审批' };
/** Said wherever extra hosts come to be listed: on the connection form, and on a draft that brings some. */
export const hostedSuffixText =
  '不要登记公共托管后缀，如 *.workers.dev、*.blob.core.windows.net、*.github.io：这些后缀下任何人都能注册子域名。';

/** The encrypted export is a binary download, so it cannot go through the JSON helper. */
export async function downloadExport(recipient: string) {
  const r = await send('/admin/backup/export', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ recipient }),
  });
  if (!r.ok) {
    const json = r.headers.get('content-type')?.split(';')[0] === 'application/json';
    throw fault(json ? String(((await r.json()) as { error?: string }).error ?? 'request_failed') : 'request_failed');
  }
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = `clavifer-${new Date().toISOString().slice(0, 10)}.age`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
/** Forms stay uncontrolled; values are read from FormData on submit. */
export const fv = (f: FormData, name: string) => String(f.get(name) ?? '');
export const lines = (value: string) =>
  value
    .split(/\r?\n/)
    .map((v) => v.trim())
    .filter(Boolean);

export const parseAuth = (c: Connection) => JSON.parse(c.auth_json) as ConnectionAuth;
export const parsePolicy = (c: Connection) => JSON.parse(c.policy_json) as ConnectionPolicy;
// An update also carries what the server recorded on submission: the connection's updated_at and the
// tests' decisions under the policy it had then.
export const parseRequested = (p: Pending) =>
  JSON.parse(p.requested_json) as
    | { grants: RequestedGrant[]; invocation?: never; setup?: never; update?: never }
    | { invocation: Invocation; grants?: never; setup?: never; update?: never }
    | { setup: Setup; grants?: never; invocation?: never; update?: never }
    | { update: Update; current: string[]; updatedAt: number; grants?: never; invocation?: never; setup?: never };
export const clientName = (s: Status, id: string) => s.clients.find((c) => c.clientId === id)?.name ?? id;
export const resourceName = (s: Status, id: string) =>
  s.secrets.find((x) => x.id === id)?.name ?? s.connections.find((x) => x.id === id)?.name ?? id;
export const fieldText = (fields: string[] | null | undefined) =>
  fields?.length ? '字段 ' + fields.join('、') : '全部字段';
export const authTypeText: Record<string, string> = {
  none: '无需凭据',
  bearer: 'Bearer Token',
  header: '自定义请求头',
  basic: '用户名与密码',
  query: 'URL 参数',
};
export const timeText = (value: number | null | undefined) =>
  value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—';
export function relativeText(value: number) {
  const diff = value - Date.now();
  const abs = Math.abs(diff);
  if (abs < 60000) return '刚刚';
  const unit = abs < 3600000 ? '分钟' : abs < 86400000 ? '小时' : '天';
  const size = abs < 3600000 ? 60000 : abs < 86400000 ? 3600000 : 86400000;
  const count = Math.round(abs / size);
  return diff >= 0 ? `${count} ${unit}后` : `${count} ${unit}前`;
}
