// The connection form's settings for the four kinds that sign or exchange. The fields are uncontrolled:
// each starts from what authToForm made of the stored auth or a preset, and formToAuth reads them back.
import { useState } from 'react';
import { JWT_ALGS, KEY_ENCODINGS } from '../../../../packages/core/jwt';
import type { FormValues } from '../auth-form';
import { Field } from '../ui';

export const TOKEN_TYPES = ['jwt', 'oauth-client', 'oauth-jwt', 'oauth-refresh'] as const;
export type TokenType = (typeof TOKEN_TYPES)[number];
export const isTokenType = (type: string): type is TokenType => (TOKEN_TYPES as readonly string[]).includes(type);

/** Offers only the bound credential's own fields: keeps the given name if the credential has it, else its only field. */
export function FieldSelect({ name, fields, value }: { name: string; fields: string[]; value: string }) {
  return (
    <select name={name} required defaultValue={fields.includes(value) ? value : fields.length === 1 ? fields[0] : ''}>
      <option value="">请选择</option>
      {fields.map((f) => (
        <option key={f} value={f}>
          {f}
        </option>
      ))}
    </select>
  );
}
/** A field the form does not show, carried as authToForm made it. */
const Hidden = ({ form, name }: { form: FormValues; name: string }) =>
  form[name] === undefined ? null : <input type="hidden" name={name} value={form[name]} />;

const CLIENT_METHODS: Record<string, string> = {
  basic: 'HTTP Basic（client_secret_basic）',
  post: '放在请求体（client_secret_post）',
  jwt: '私钥签名的断言（private_key_jwt）',
  none: '公共客户端，只带客户端 ID',
  '': '不需要',
};
// Which client authentications each kind takes, as the server's schema allows them.
const clientMethods: Record<Exclude<TokenType, 'jwt'>, string[]> = {
  'oauth-client': ['basic', 'post', 'jwt'],
  'oauth-jwt': ['', 'basic', 'post'],
  'oauth-refresh': ['basic', 'post', 'jwt', 'none'],
};

/** How to sign a JWT; prefix keeps the connection's own JWT and a client's assertion apart in the form. */
function JwtFields({
  prefix,
  form,
  fields,
  secretId,
  assertion,
}: {
  prefix: string;
  form: FormValues;
  fields: string[];
  secretId: string;
  /** A client assertion, which always carries a jti. */
  assertion?: boolean;
}) {
  const [alg, setAlg] = useState(form[prefix + 'alg'] ?? 'RS256');
  return (
    <>
      <div className="field-row field-row--pair">
        <Field label="签名算法">
          <select name={prefix + 'alg'} value={alg} onChange={(e) => setAlg(e.target.value)}>
            {JWT_ALGS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </Field>
        <Field label="密钥字段">
          <FieldSelect
            key={secretId}
            name={prefix + 'keyField'}
            fields={fields}
            value={form[prefix + 'keyField'] ?? 'private_key'}
          />
        </Field>
      </div>
      {alg.startsWith('HS') ? (
        <Field
          label="密钥编码"
          hint="对称密钥在字段里的写法：utf8 是原文本身，另有 base64、base64url 和十六进制（hex）。"
        >
          <select name={prefix + 'keyEncoding'} defaultValue={form[prefix + 'keyEncoding'] ?? 'utf8'}>
            {KEY_ENCODINGS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
        </Field>
      ) : (
        <p className="note">
          私钥字段可以是 PEM（PKCS#8、PKCS#1、SEC1）或 JWK。带口令的私钥在凭据表单里用口令解开后再保存。
        </p>
      )}
      <Field
        label="JWT header（JSON，可选）"
        hint='例如 {"kid": {"$field": "private_key_id"}}；{"$field": "字段名"} 取凭据字段的值。alg 按签名算法自动写，不能写在这里。'
      >
        <textarea
          name={prefix + 'header'}
          rows={2}
          placeholder='{"kid": "…"}'
          defaultValue={form[prefix + 'header'] ?? ''}
        />
      </Field>
      <Field
        label="claims（JSON）"
        hint='值可以是任意 JSON；{"$field": "字段名"} 取凭据字段的值。iat、exp 按有效期自动写，jti 由下面的选项决定，三者都不能写在这里。aud 没有默认值，按上游的要求写。'
      >
        <textarea
          name={prefix + 'claims'}
          rows={5}
          required
          placeholder='{"iss": {"$field": "client_email"}, "aud": "https://oauth2.googleapis.com/token"}'
          defaultValue={form[prefix + 'claims'] ?? ''}
        />
      </Field>
      <Field label="JWT 有效期（秒）" hint="10 到 3600。iat 是签发时刻，exp 是 iat 加有效期。">
        <input
          name={prefix + 'lifetime'}
          type="number"
          min={10}
          max={3600}
          required
          defaultValue={form[prefix + 'lifetime'] ?? '300'}
        />
      </Field>
      {assertion ? (
        <>
          <p className="note">客户端断言每次都带一个随机 jti。</p>
          <Hidden form={form} name={prefix + 'jti'} />
        </>
      ) : (
        <>
          <label className="check">
            <input
              type="checkbox"
              name={prefix + 'jti'}
              value="true"
              defaultChecked={form[prefix + 'jti'] === 'true'}
            />
            <span>每次带一个随机 jti</span>
          </label>
          <Hidden form={form} name={prefix + 'jtiFalse'} />
        </>
      )}
    </>
  );
}

/** How the connection proves which client it is to the token endpoint. */
function ClientFields({
  type,
  form,
  fields,
  secretId,
}: {
  type: Exclude<TokenType, 'jwt'>;
  form: FormValues;
  fields: string[];
  secretId: string;
}) {
  const methods = clientMethods[type];
  const stored = form['client.method'];
  const [method, setMethod] = useState(stored !== undefined && methods.includes(stored) ? stored : methods[0]);
  return (
    <>
      <Field label="客户端认证方式">
        <select name="client.method" value={method} onChange={(e) => setMethod(e.target.value)}>
          {methods.map((m) => (
            <option key={m} value={m}>
              {CLIENT_METHODS[m]}
            </option>
          ))}
        </select>
      </Field>
      {method ? (
        <div className="field-row field-row--pair">
          <Field
            label="客户端 ID 取自"
            hint={method === 'basic' || method === 'post' ? '必填。' : '可选；在控制台授权时必填。'}
          >
            <select
              key={secretId}
              name="client.idField"
              // Only a client the form starts without reads its id from the usual field by default; a
              // stored client keeps where its id comes from, or that it has none.
              defaultValue={form['client.idField'] ?? (fields.includes('client_id') ? 'client_id' : '')}
            >
              <option value="">直接填写（右侧）</option>
              {fields.map((f) => (
                <option key={f} value={f}>
                  凭据字段 {f}
                </option>
              ))}
            </select>
          </Field>
          <Field label="客户端 ID">
            <input name="client.id" autoComplete="off" defaultValue={form['client.id'] ?? ''} />
          </Field>
        </div>
      ) : null}
      {method === 'basic' || method === 'post' ? (
        <Field label="客户端密钥字段">
          <FieldSelect
            key={secretId}
            name="client.secretField"
            fields={fields}
            value={form['client.secretField'] ?? 'client_secret'}
          />
        </Field>
      ) : null}
      {method === 'jwt' ? (
        <JwtFields prefix="client.jwt." form={form} fields={fields} secretId={secretId} assertion />
      ) : null}
    </>
  );
}

/** The settings of the kinds that sign or exchange; remounted whenever the values it starts from change. */
export function TokenAuthFields({
  type,
  form,
  fields,
  secretId,
}: {
  type: TokenType;
  form: FormValues;
  fields: string[];
  secretId: string;
}) {
  const [authorizing, setAuthorizing] = useState(!!form.authorizing);
  const exchange = type !== 'jwt';
  return (
    <>
      {type === 'jwt' || type === 'oauth-jwt' ? (
        <fieldset>
          <legend>{type === 'jwt' ? '每个请求签一个 JWT' : 'JWT 断言'}</legend>
          <JwtFields prefix="jwt." form={form} fields={fields} secretId={secretId} />
        </fieldset>
      ) : null}
      {exchange ? (
        <fieldset>
          <legend>token 端点</legend>
          <Field label="token 端点地址" hint="凭据的第二个去处：https、公网主机，可以带路径，不带查询串。">
            <input
              name="tokenUrl"
              type="url"
              required
              placeholder="https://oauth2.example.com/token"
              defaultValue={form.tokenUrl ?? ''}
            />
          </Field>
          <div className="field-row field-row--pair">
            <Field label="请求体格式">
              <select name="bodyFormat" defaultValue={form.bodyFormat ?? ''}>
                <option value="">表单（application/x-www-form-urlencoded）</option>
                {/* Only a stored auth that names the default keeps it named. */}
                {form.bodyFormat === 'form' ? <option value="form">表单（配置里写明了 form）</option> : null}
                <option value="json">JSON</option>
              </select>
            </Field>
            <Field label="token 有效期（秒，可选）" hint="回复里没有 expires_in 时用它。">
              <input name="ttl" type="number" min={1} max={31536000} defaultValue={form.ttl ?? ''} />
            </Field>
          </div>
          {type === 'oauth-client' ? (
            <div className="field-row field-row--pair">
              <Field label="grant 名（可选）" hint="默认 client_credentials；Zoom 是 account_credentials。">
                <input name="grantType" placeholder="client_credentials" defaultValue={form.grantType ?? ''} />
              </Field>
              <Field label="scope（可选）">
                <input name="scope" defaultValue={form.scope ?? ''} />
              </Field>
            </div>
          ) : null}
          {type === 'oauth-refresh' ? (
            <div className="field-row field-row--pair">
              <Field
                label="refresh token 字段"
                hint={authorizing ? '在控制台授权时由服务端写入，凭据里可以还没有这个字段。' : undefined}
              >
                <input
                  name="refreshField"
                  required
                  list="refresh-fields"
                  pattern="[A-Za-z_][A-Za-z0-9_\-]*"
                  defaultValue={form.refreshField ?? 'refresh_token'}
                />
                <datalist id="refresh-fields">
                  {fields.map((f) => (
                    <option key={f} value={f} />
                  ))}
                </datalist>
              </Field>
              <Field label="刷新时的 scope（可选）" hint="只在要收窄权限时填。">
                <input name="scope" defaultValue={form.scope ?? ''} />
              </Field>
            </div>
          ) : null}
          <Field
            label="额外参数（可选）"
            hint="每行一个「名称=值」，随 token 请求一起发送，例如 audience、resource、account_id。grant_type、scope、client_id 这类由服务端写的名称不能用。"
          >
            <textarea
              name="params"
              rows={2}
              placeholder="audience=https://api.example.com"
              defaultValue={form.params ?? ''}
            />
          </Field>
          <Hidden form={form} name="params.empty" />
        </fieldset>
      ) : null}
      {exchange ? (
        <fieldset>
          <legend>客户端认证</legend>
          <ClientFields type={type} form={form} fields={fields} secretId={secretId} />
        </fieldset>
      ) : null}
      {type === 'oauth-refresh' ? (
        <fieldset>
          <legend>在控制台授权</legend>
          <label className="check">
            <input
              type="checkbox"
              name="authorizing"
              checked={authorizing}
              onChange={(e) => setAuthorizing(e.target.checked)}
            />
            <span>保存后在这里登录上游授权，refresh token 直接写进凭据</span>
          </label>
          {authorizing ? (
            <>
              <Field
                label="授权地址"
                hint="你的浏览器会被带到这里登录：https、公网主机，可以带路径，不带查询串。保存后连接上会显示要登记到上游的回调地址。"
              >
                <input
                  name="authorize.url"
                  type="url"
                  required
                  placeholder="https://accounts.example.com/oauth2/authorize"
                  defaultValue={form['authorize.url'] ?? ''}
                />
              </Field>
              <Field label="授权 scope（可选）" hint="原样发送，分隔符按上游的要求写（多数用空格，Linear 用逗号）。">
                <input name="authorize.scope" defaultValue={form['authorize.scope'] ?? ''} />
              </Field>
              <Field
                label="授权参数（可选）"
                hint="每行一个「名称=值」，例如 Google 的 access_type=offline 和 prompt=consent。response_type、client_id、redirect_uri、state、PKCE 参数和 scope 由服务端写。"
              >
                <textarea
                  name="authorize.params"
                  rows={2}
                  placeholder="access_type=offline"
                  defaultValue={form['authorize.params'] ?? ''}
                />
              </Field>
              <Hidden form={form} name="authorize.params.empty" />
            </>
          ) : null}
        </fieldset>
      ) : null}
      <fieldset>
        <legend>{exchange ? '换得的 token 怎样发往上游' : 'JWT 怎样发往上游'}</legend>
        <div className="field-row field-row--pair">
          <Field label="请求头" hint="留空即 Authorization。">
            <input name="tokenHeader" placeholder="Authorization" defaultValue={form.tokenHeader ?? ''} />
          </Field>
          <Field label="前缀" hint="留空即 Bearer。">
            <input name="tokenScheme" placeholder="Bearer" defaultValue={form.tokenScheme ?? ''} />
          </Field>
        </div>
        <label className="check">
          <input type="checkbox" name="noScheme" defaultChecked={!!form.noScheme} />
          <span>不带前缀，请求头里只放 token</span>
        </label>
      </fieldset>
    </>
  );
}
