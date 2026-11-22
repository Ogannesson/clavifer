// Every management call goes through here so error codes reach the user as one consistent sentence.
import { authorizes, type Auth, type DraftAuth } from '../../../packages/core/auth';

export type Secret = {
  id: string;
  name: string;
  description: string;
  current_version: number;
  updated_at: number;
  fields: string[];
};
export type ConnectionAuth = Auth;
export type { DraftAuth };
export type Connection = {
  id: string;
  name: string;
  origin: string;
  description: string;
  auth_json: string;
  policy_json: string;
  updated_at: number;
  /** For a connection the Owner authorizes in the console: the address to register upstream. */
  callback?: string;
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
  /** For a setup: the callback of each connection it creates that the Owner authorizes, by its id. */
  callbacks?: Record<string, string>;
};
/** What a token endpoint answered when it refused, as the Owner's routes pass it on: its host always,
 * the rest when it answered. */
export type TokenEndpoint = { host?: string; status?: number; error?: string; error_description?: string };
/** A connection of an approved setup or a completed authorization that still needs the Owner. */
export type Warning = { connection: string; error: string; hint?: string; token_endpoint?: TokenEndpoint };
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
  archiveError: string | null;
  unsealedBytes: number;
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
  cross_site_request: '完整导出只能从本站的备份页面发起，来自其他网站或直接打开的链接已被拒绝。',
  invalid_bootstrap_token: '令牌不正确、已过期或已经用过，请重新签发一个。',
  already_initialized: '本服务已经有管理员，请直接登录；忘记密码时用找回令牌重置。',
  not_initialized: '本服务还没有管理员，这个令牌只能用来创建管理员或导入快照。',
  invalid_snapshot: '快照文件不符合格式，无法导入。',
  snapshot_from_newer_version:
    '这份快照由更新版本的 Clavifer 写出，本服务读不了。请先把本服务升级到同一或更新的版本，再导入。',
  backup_has_unconvertible_rule:
    '快照里有连接的规则含字面的 { 或 }。本版本把它们当作通配符，规则的含义会变，因此拒绝导入。请在导出它的版本里把这条规则中的 { 和 } 改写成 %7B 和 %7D，重新导出后再导入。',
  snapshot_inconsistent: '快照里的记录互相对不上（例如授权指向快照里没有的安装实例），无法导入。',
  import_incomplete: '收到的记录数与快照末尾的计数不一致，可能漏传了一部分，导入没有完成。请重新签发令牌后再导入一次。',
  import_superseded: '这次导入已失效：实例已经初始化，或者有人用新令牌重新开始了导入。',
  version_conflict: '凭据在这期间被更新了（在别处保存过，或服务端轮换了 refresh token），请刷新页面后重新操作。',
  insufficient_scope: '当前没有这项资源的使用权限。',
  existing_grant_conflict: '该资源已有字段范围不同的有效授权。请先在授权表单手工调整该授权，再批准或拒绝此申请。',
  use_path_prefix_not_glob: '路径请输入 /v1 这样的前缀，不使用星号。',
  invalid_rule:
    '格式不正确：每行写「方法 路径」或只写路径，方法为 GET、POST 等或 *，路径以 / 开头，不含 ; 和控制字符。一段用 {名字}（每段最多一个，前后可带文字，如 {r}:setIamPolicy），任意多段用 **，末尾的 /* 表示含子路径；其他位置不能写 *、{ 或 }。例如 DELETE /v1/items/{id}、* /**/{r}:setIamPolicy。',
  too_many_rules: '超过 50 条上限，请合并为带 /* 的前缀规则。',
  invalid_host:
    '写法不正确：每行一个小写域名（如 artifacts.example.com）或 *.后缀（如 *.example.com，* 后至少两段），不带 https://、端口和路径，不能是 IP 或本地域名；中文等域名写成 xn-- 形式。',
  public_origin_required: '连接地址必须是管理员信任的公网域名。',
  origin_must_be_https: '连接地址必须是 https:// 开头的公网域名。',
  origin_must_not_contain_path: '服务地址只填 origin（如 https://api.example.com），不带路径、查询串和用户名。',
  endpoint_must_not_contain_query:
    '地址不能带查询串、# 片段或用户名；要发给 token 端点或授权页的额外参数，写在「额外参数」或「授权参数」里。',
  invalid_query:
    '查询参数不符合要求：最多 100 个，名称不含空格和控制字符；也不能带会改写 HTTP 方法或请求头的参数（如 $httpMethod）。',
  // Exchanging the credential for a token: on saving a connection, approving a setup or authorizing.
  token_exchange_failed:
    'token 端点拒绝了换 token 的请求，或回复里没有可用的 access token。请检查 token 端点地址、客户端认证、scope 和凭据字段。',
  token_unavailable: 'token 端点暂时不可用（超时、连不上、服务端出错或限流），请稍后重试。',
  invalid_key_credential:
    '密钥字段解析不了，或和所选算法不配：私钥要是 PEM 或 JWK，加密私钥要先在凭据表单里用口令解开；HS 算法的密钥按所选的密钥编码填写。',
  ttl_required: 'token 端点的回复里没有有效期（expires_in），请在连接上填写 token 有效期（秒）。',
  authorization_expired:
    '这次授权已失效：超过了 10 分钟、已经完成过，或不是从当前登录会话发起的。请回到 API 连接页重新点授权。',
  no_refresh_token:
    '上游没有发回 refresh token，什么都没有保存。请检查连接的授权参数和 scope：Google 要加授权参数 access_type=offline 和 prompt=consent，Microsoft 要在 scope 里加 offline_access，Atlassian 要 scope 加 offline_access、授权参数加 prompt=consent，Dropbox 要加授权参数 token_access_type=offline。',
  authorization_not_configured: '只有填了授权地址的 refresh token 连接才能在控制台授权。',
  client_id_required: '授权请求要带客户端 ID：请在连接的客户端认证里填写客户端 ID，或选择存放它的凭据字段。',
  unsupported_key_encryption: '这个私钥的加密方式浏览器解不开，请先用 openssl 转换。',
  key_decryption_failed: '口令不对，或文件已损坏。',
  connection_not_found: '找不到这条连接，可能已被删除，请刷新后重试。',
  invalid_json: '提交的内容不是合法的 JSON，请刷新页面后重试。',
  json_required: '提交的内容格式不对，请刷新页面后重试。',
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
  conflict: '存在同名或重复的记录，请换一个名称。',
  endpoint_disabled: '此接口在本服务中已关闭。',
  body_too_large: '提交的内容超出大小限制。',
  headers_too_large: '请求头总量超出大小限制。',
  invalid_backup_recipient: 'age 公钥格式不正确。请填写公钥接收者，不能填写私钥。',
  backup_not_found: '还没有可下载的备份。',
  backup_failed: '备份暂未成功，稍后会重试；请保留已有备份。',
  // A snapshot of an inconsistent instance is refused whole: the automatic backup and the full export alike.
  backup_has_broken_connection:
    '有 API 连接绑定的凭据不存在或缺少所需字段。修复或删除这个连接之前，自动备份和完整导出都会被拒绝，不写出任何内容。',
  backup_has_missing_versions: '有凭据缺少历史版本。在修复之前，自动备份和完整导出都会被拒绝，不写出任何内容。',
  backup_has_dangling_reference:
    '有授权或访问申请指向已不存在的安装实例或资源。在修复之前，自动备份和完整导出都会被拒绝，不写出任何内容。',
  backup_unrepresentable:
    '有记录不符合快照格式（例如早期版本留下的设置）。在修复之前，自动备份和完整导出都会被拒绝，不写出任何内容。',
  archive_identity_missing:
    '数据库里缺少归档身份（创建 Owner 时生成），没有它就读不出已封存的冷数据。自动备份和完整导出都会被拒绝，不写出任何内容。',
  archive_segment_unavailable:
    '存储桶里缺少一个已封存的冷数据文件，或它的校验和与记录不符，完整导出已取消，没有写出任何内容。',
  backup_storage_failed: '加密副本写入存储失败，请稍后重试。',
  backup_state_unavailable: '备份状态暂时不可读，请稍后重试。',
  hot_data_over_limit:
    '热数据超限：尚未封存的数据超过 9 MB，本次自动备份已跳过。旧的审计和访问申请封存后会自动恢复；如果凭据和连接本身就这么多，请改用完整导出。',
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
  /** What a token endpoint said when it refused, which the page that acted keeps in view (EndpointRefusal). */
  endpoint?: TokenEndpoint;
  constructor(code: string, text: string) {
    super(text);
    this.code = code;
  }
}
// Upstream English messages are never shown; an unmapped code still names itself for troubleshooting.
export const fault = (code: string) => new Fault(code, errorText[code] ?? `操作失败（${code}）。`);
// What stopped sealing, which moves old audit rows and access requests out of the hot tables. Until it
// runs again they stay there, so the hot data keeps growing.
const archiveErrorText: Record<string, string> = {
  archive_failed: '读写存储或数据库时出错，下一次计划任务会重试。',
  archive_conflict:
    '要封存的一段记录在读出之后又多出了行，这不应发生；本次没有封存，下一次计划任务会重新读取。反复出现时请查看服务日志。',
  backup_unrepresentable: '有旧的审计或访问申请不符合封存格式，封存已停下，这些记录留在热表里。',
  snapshot_line_too_long: '有一条旧记录超过单行长度上限，无法封存，封存已停下。',
  encryption_key_missing: '归档身份无法用当前根密钥解开，无法封存。',
  archive_identity_missing: '数据库里缺少归档身份（创建 Owner 时生成），无法封存。',
};
export const archiveErrorMessage = (code: string) => archiveErrorText[code] ?? `封存失败（${code}）。`;
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

/** Runs each load it is given but applies its answer only when no load started after it has applied its
 * own: a poll that started before an action's own refresh, or before a sign-out, and arrives after it
 * must not bring back what that changed. Each call resolves with what it loaded either way. */
export function inOrder<T>(apply: (value: T) => void) {
  let started = 0;
  let applied = 0;
  return async (load: () => Promise<T>) => {
    const call = ++started;
    const value = await load();
    if (call > applied) {
      applied = call;
      apply(value);
    }
    return value;
  };
}
/** Whether the page the server now serves at / no longer loads script, the entry script this page runs:
 * a deployment since replaced it. */
export const replaced = (html: string, script: string) => !html.includes(`src="${script}"`);

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
    // An endpoint of the connection's auth is checked like its origin; say which of the two is wrong.
    const endpoint = String(value.hint ?? '').match(/^auth\.(tokenUrl|authorize\.url)\b/);
    if (endpoint) e.message = `「${endpoint[1] === 'tokenUrl' ? 'token 端点' : '授权地址'}」${e.message}`;
    // A refused form names its members by path (auth.jwt.claims), which says where to look.
    if (e.code === 'invalid_input' && value.hint)
      e.message += `（有问题的项：${[...String(value.hint).matchAll(/(?:^|; )([^:;]+):/g)].map((m) => m[1]).join('、')}）`;
    if (e.code === 'invalid_key_credential') e.message = keyText(value.hint) ?? e.message;
    if (value.token_endpoint) e.endpoint = value.token_endpoint as TokenEndpoint;
    // Which record of a refused snapshot is wrong, as the service names it.
    if (
      value.hint &&
      ['invalid_snapshot', 'snapshot_inconsistent', 'import_incomplete', 'backup_has_unconvertible_rule'].includes(
        e.code,
      )
    )
      e.message += `（${String(value.hint)}）`;
    throw e;
  }
  return value;
}
// Why a key cannot be read, one text for each reason invalid() in packages/core/jwt.ts gives.
const keyReasonText: [RegExp, (part: string) => string][] = [
  [/^is not valid (\w+)$/, (encoding) => `按所选的密钥编码 ${encoding} 解不开`],
  [/^is empty$/, () => '解码后是空的'],
  [/^is neither a PEM private key nor a JSON Web Key$/, () => '既不是 PEM 私钥，也不是 JWK'],
  [/^is encrypted: /, () => '带口令加密，服务用不了：请在凭据表单里载入它，用口令解开后再保存'],
  [
    /^is a PEM whose body is not base64$/,
    () =>
      '是 PEM，但正文不是 base64。从 JSON 文件里复制出来的私钥，换行常常是字面的 \\n：请用「从 JSON 文件填入」，或把它重新粘贴到字段里，控制台会换回换行。复制时只选引号里的内容（连同引号也可以），后面的逗号或空格不会被去掉',
  ],
  [/^is an EC PRIVATE KEY that names no curve$/, () => '是 EC PRIVATE KEY，但没有写明曲线'],
  [
    /^is a PEM "(.+)", which is not a format this service reads$/,
    (label) => `是 PEM「${label}」，本服务读不了这种格式`,
  ],
  [/^starts with "\{" but is not JSON$/, () => '以 { 开头，但不是 JSON'],
  [/^is not a private key for (\w+)$/, (alg) => `不是 ${alg} 能用的私钥，密钥类型和所选算法不配`],
];
/** What an invalid_key_credential hint says, in Chinese: the field and the reason. Undefined for a hint
 * of another shape, which leaves the generic text. */
export function keyText(hint: unknown) {
  const [, field, reason] = String(hint ?? '').match(/^The key in field "([^"]+)" (.+)\.$/) ?? [];
  for (const [pattern, text] of keyReasonText) {
    const m = reason?.match(pattern);
    if (m) return `字段「${field}」里的密钥${text(m[1])}。`;
  }
}
/** A connection an approved setup created whose credential then failed its try, as the page says it. */
export const warningText = (w: Warning) =>
  (w.error === 'invalid_key_credential' && keyText(w.hint)) || fault(w.error).message;
export const ruleKindText: Record<string, string> = { deny: '拒绝', approval: '必须单次审批', free: '免审批' };
/** Said wherever extra hosts come to be listed: on the connection form, and on a draft that brings some. */
export const hostedSuffixText =
  '不要登记公共托管后缀，如 *.workers.dev、*.blob.core.windows.net、*.github.io：这些后缀下任何人都能注册子域名。';

/** The full export streams straight to disk through a link download, which neither holds the file in
 * the page nor tells it when the download ends. The random id it carries names the export in the
 * audit, where the server records that it wrote the last byte; returns that id. */
export function startFullExport(recipient: string) {
  // The recipient goes into the address, so a private key pasted by mistake must never get that far.
  if (!/^age1[0-9a-z]+$/.test(recipient)) throw fault('invalid_backup_recipient');
  const id = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const a = document.createElement('a');
  a.href = `/admin/backup/export?${new URLSearchParams({ recipient, id })}`;
  a.download = '';
  a.click();
  return id;
}
export type ExportStatus = { status: 'complete' | 'started' | 'unknown' | 'failed'; error?: string };

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
    | {
        setup: Setup;
        // Fixed on submission: the credential's id and each connection's, in the order of connections.
        ids: { secretId?: string; connectionIds: string[] };
        grants?: never;
        invocation?: never;
        update?: never;
      }
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
  jwt: '签名 JWT',
  'oauth-client': 'OAuth 客户端凭据换 token',
  'oauth-jwt': 'JWT 断言换 token',
  'oauth-refresh': 'Refresh Token 换 token',
};
/** A connection the Owner authorizes in the console whose credential holds no refresh token yet. */
export const awaitingAuthorization = (auth: ConnectionAuth, secrets: Secret[]) =>
  authorizes(auth) && !secrets.find((s) => s.id === auth.secretId)?.fields.includes(auth.refreshField);
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
