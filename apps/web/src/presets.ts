// Starting points for the connection form: how each upstream in the design's vendor table exchanges or
// signs its credential, as its documentation said on the day named. Only the console knows these; they
// are never stored, and a connection made from one is an ordinary connection. A {name} in a value is a
// placeholder the Owner replaces with their tenant, domain, shop, account or scope before saving.
import type { DraftAuth } from '../../../packages/core/auth';

export type Preset = {
  id: string;
  label: string;
  /** The API's origin, when the upstream has one fixed address (or one with a placeholder). */
  origin: string;
  auth: DraftAuth;
  /** What to know besides the values: where a value comes from, an upstream setting to turn on. */
  note?: string;
  source: string[];
  checked: string;
};
const checked = '2026-11-21';
const client = (method: 'basic' | 'post') => ({ method, id: { $field: 'client_id' }, secretField: 'client_secret' });
const refresh = { refreshField: 'refresh_token' } as const;

export const PRESETS: Preset[] = [
  {
    id: 'google-service-account',
    label: 'Google 服务账号',
    origin: 'https://{service}.googleapis.com',
    auth: {
      type: 'oauth-jwt',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      jwt: {
        alg: 'RS256',
        keyField: 'private_key',
        header: { kid: { $field: 'private_key_id' } },
        claims: {
          iss: { $field: 'client_email' },
          scope: 'https://www.googleapis.com/auth/cloud-platform',
          aud: 'https://oauth2.googleapis.com/token',
        },
        lifetime: 3600,
      },
    },
    note: '把服务账号的 JSON 密钥文件用凭据表单的「从 JSON 文件填入」载入，得到 client_email、private_key、private_key_id 等字段。scope 按要调的 API 改。',
    source: ['https://developers.google.com/identity/protocols/oauth2/service-account'],
    checked,
  },
  {
    id: 'google-service-account-self-signed',
    label: 'Google 服务账号（自签 JWT）',
    origin: 'https://{service}.googleapis.com',
    auth: {
      type: 'jwt',
      jwt: {
        alg: 'RS256',
        keyField: 'private_key',
        header: { kid: { $field: 'private_key_id' } },
        claims: {
          iss: { $field: 'client_email' },
          sub: { $field: 'client_email' },
          aud: 'https://{service}.googleapis.com/',
        },
        lifetime: 3600,
      },
    },
    note: '只对在 googleapis 仓库有公开服务定义的 API 有效；GCP 连接一般用上一个预设。',
    source: [
      'https://google.aip.dev/auth/4111',
      'https://developers.google.com/identity/protocols/oauth2/service-account',
    ],
    checked,
  },
  {
    id: 'entra-secret',
    label: 'Microsoft Entra 应用密钥',
    origin: 'https://graph.microsoft.com',
    auth: {
      type: 'oauth-client',
      tokenUrl: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
      client: client('post'),
      scope: 'https://graph.microsoft.com/.default',
    },
    note: 'scope 写成「资源/.default」，一次只能一个资源；调 ARM 时改成 https://management.azure.com/.default。',
    source: ['https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow'],
    checked,
  },
  {
    id: 'entra-certificate',
    label: 'Microsoft Entra 证书',
    origin: 'https://graph.microsoft.com',
    auth: {
      type: 'oauth-client',
      tokenUrl: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
      client: {
        method: 'jwt',
        id: { $field: 'client_id' },
        jwt: {
          alg: 'PS256',
          keyField: 'private_key',
          header: { 'x5t#S256': '{thumbprint}' },
          claims: {
            aud: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
            iss: { $field: 'client_id' },
            sub: { $field: 'client_id' },
          },
          lifetime: 600,
        },
      },
      scope: 'https://graph.microsoft.com/.default',
    },
    note: 'x5t#S256 是证书 DER 的 SHA-256 摘要的 base64url。',
    source: ['https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials'],
    checked,
  },
  {
    id: 'okta-service',
    label: 'Okta 服务应用',
    origin: 'https://{domain}',
    auth: {
      type: 'oauth-client',
      tokenUrl: 'https://{domain}/oauth2/v1/token',
      client: {
        method: 'jwt',
        id: { $field: 'client_id' },
        jwt: {
          alg: 'RS256',
          keyField: 'private_key',
          claims: {
            aud: 'https://{domain}/oauth2/v1/token',
            iss: { $field: 'client_id' },
            sub: { $field: 'client_id' },
          },
          lifetime: 300,
        },
      },
      scope: 'okta.users.read',
    },
    note: 'Okta 控制台给的是 JWK，可以直接存进私钥字段，也可以切换成 PEM。',
    source: ['https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/'],
    checked,
  },
  {
    id: 'auth0-m2m',
    label: 'Auth0 机器对机器应用',
    origin: 'https://{domain}',
    auth: {
      type: 'oauth-client',
      tokenUrl: 'https://{domain}/oauth/token',
      client: client('post'),
      params: { audience: 'https://{domain}/api/v2/' },
    },
    note: '示例的 audience 是 Auth0 Management API；调你自己的 API 时改成它的标识，服务地址改成它的主机。',
    source: ['https://auth0.com/docs/api/authentication/client-credential-flow/get-token'],
    checked,
  },
  {
    id: 'paypal',
    label: 'PayPal',
    origin: 'https://api-m.paypal.com',
    auth: { type: 'oauth-client', tokenUrl: 'https://api-m.paypal.com/v1/oauth2/token', client: client('basic') },
    note: '沙箱把两处 api-m.paypal.com 换成 api-m.sandbox.paypal.com。',
    source: ['https://developer.paypal.com/api/rest/authentication/'],
    checked,
  },
  {
    id: 'spotify-app',
    label: 'Spotify（应用级）',
    origin: 'https://api.spotify.com',
    auth: { type: 'oauth-client', tokenUrl: 'https://accounts.spotify.com/api/token', client: client('basic') },
    source: ['https://developer.spotify.com/documentation/web-api/tutorials/client-credentials-flow'],
    checked,
  },
  {
    id: 'shopify',
    label: 'Shopify Dev Dashboard 应用',
    origin: 'https://{shop}.myshopify.com',
    auth: {
      type: 'oauth-client',
      tokenUrl: 'https://{shop}.myshopify.com/admin/oauth/access_token',
      client: client('post'),
      header: 'X-Shopify-Access-Token',
      scheme: '',
    },
    source: ['https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens'],
    checked,
  },
  {
    id: 'zoom-s2s',
    label: 'Zoom Server-to-Server',
    origin: 'https://api.zoom.us',
    auth: {
      type: 'oauth-client',
      tokenUrl: 'https://zoom.us/oauth/token',
      client: client('basic'),
      grantType: 'account_credentials',
      params: { account_id: '{account_id}' },
    },
    source: ['https://developers.zoom.us/docs/internal-apps/s2s-oauth/'],
    checked,
  },
  {
    id: 'salesforce-jwt',
    label: 'Salesforce JWT Bearer',
    origin: 'https://{mydomain}.my.salesforce.com',
    auth: {
      type: 'oauth-jwt',
      tokenUrl: 'https://login.salesforce.com/services/oauth2/token',
      jwt: {
        alg: 'RS256',
        keyField: 'private_key',
        claims: { iss: { $field: 'client_id' }, sub: { $field: 'username' }, aud: 'https://login.salesforce.com' },
        lifetime: 180,
      },
      ttl: 3600,
    },
    note: 'token 端点的回复没有有效期，ttl 按组织的会话超时填。沙箱把两处 login.salesforce.com 换成 test.salesforce.com。服务地址填 My Domain 主机。',
    source: ['https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_jwt_flow.htm'],
    checked,
  },
  {
    id: 'docusign-jwt',
    label: 'DocuSign JWT',
    origin: 'https://{server}.docusign.net',
    auth: {
      type: 'oauth-jwt',
      tokenUrl: 'https://account.docusign.com/oauth/token',
      jwt: {
        alg: 'RS256',
        keyField: 'private_key',
        claims: {
          iss: { $field: 'integration_key' },
          sub: { $field: 'user_id' },
          aud: 'account.docusign.com',
          scope: 'signature impersonation',
        },
        lifetime: 3600,
      },
    },
    note: 'aud 不带 https://。开发环境把 account.docusign.com 两处都换成 account-d.docusign.com。用户要先对 impersonation scope 同意一次。',
    source: ['https://developers.docusign.com/platform/auth/jwt-get-token/'],
    checked,
  },
  {
    id: 'box-jwt',
    label: 'Box JWT',
    origin: 'https://api.box.com',
    auth: {
      type: 'oauth-jwt',
      tokenUrl: 'https://api.box.com/oauth2/token',
      client: { method: 'post', id: { $field: 'clientID' }, secretField: 'clientSecret' },
      jwt: {
        alg: 'RS256',
        keyField: 'privateKey',
        header: { kid: { $field: 'publicKeyID' } },
        claims: {
          iss: { $field: 'clientID' },
          sub: { $field: 'enterpriseID' },
          box_sub_type: 'enterprise',
          aud: 'https://api.box.com/oauth2/token',
        },
        lifetime: 60,
        jti: true,
      },
    },
    note: '把 Box 下载的配置 JSON 用凭据表单的「从 JSON 文件填入」载入，字段名正好对上；文件里的 passphrase 只用来解开私钥，不存成字段。页面解不开时按提示用 openssl 转换。',
    source: ['https://developer.box.com/guides/authentication/jwt/without-sdk/'],
    checked,
  },
  {
    id: 'apple-app-store-connect',
    label: 'Apple App Store Connect',
    origin: 'https://api.appstoreconnect.apple.com',
    auth: {
      type: 'jwt',
      jwt: {
        alg: 'ES256',
        keyField: 'private_key',
        header: { kid: '{key_id}' },
        claims: { iss: '{issuer_id}', aud: 'appstoreconnect-v1' },
        lifetime: 1200,
      },
    },
    note: '私钥字段存下载的 .p8 文件内容。个人密钥把 iss 换成 "sub": "user"。',
    source: ['https://developer.apple.com/documentation/appstoreconnectapi/generating-tokens-for-api-requests'],
    checked,
  },
  {
    id: 'ghost-admin',
    label: 'Ghost Admin API',
    origin: 'https://{site}',
    auth: {
      type: 'jwt',
      jwt: {
        alg: 'HS256',
        keyField: 'secret',
        keyEncoding: 'hex',
        header: { kid: { $field: 'key_id' } },
        claims: { aud: '/admin/' },
        lifetime: 300,
      },
      scheme: 'Ghost',
    },
    note: 'Admin API key 形如 id:secret，冒号前存进字段 key_id，冒号后存进字段 secret。',
    source: ['https://docs.ghost.org/admin-api#token-authentication'],
    checked,
  },
  {
    id: 'livekit',
    label: 'LiveKit 服务端 API',
    origin: 'https://{project}.livekit.cloud',
    auth: {
      type: 'jwt',
      jwt: {
        alg: 'HS256',
        keyField: 'api_secret',
        keyEncoding: 'utf8',
        claims: { iss: { $field: 'api_key' }, video: { roomCreate: true, roomList: true, roomAdmin: true } },
        lifetime: 600,
      },
    },
    note: 'video 里放这个连接需要的权限。',
    source: ['https://docs.livekit.io/reference/other/roomservice-api/'],
    checked,
  },
  {
    id: 'google-user',
    label: 'Google 用户授权',
    origin: 'https://{service}.googleapis.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://oauth2.googleapis.com/token',
      client: client('post'),
      authorize: {
        url: 'https://accounts.google.com/o/oauth2/v2/auth',
        scope: 'https://www.googleapis.com/auth/{scope}',
        params: { access_type: 'offline', prompt: 'consent' },
      },
    },
    note: 'OAuth 客户端选 Web 应用类型。发布状态为 Testing 的应用，refresh token 7 天过期。',
    source: ['https://developers.google.com/identity/protocols/oauth2/web-server'],
    checked,
  },
  {
    id: 'microsoft-user',
    label: 'Microsoft 委托权限',
    origin: 'https://graph.microsoft.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
      client: client('post'),
      authorize: {
        url: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',
        scope: 'offline_access https://graph.microsoft.com/User.Read',
      },
    },
    note: 'tenant 可以是租户 ID，或 common、organizations、consumers。',
    source: ['https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow'],
    checked,
  },
  {
    id: 'atlassian',
    label: 'Atlassian',
    origin: 'https://api.atlassian.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://auth.atlassian.com/oauth/token',
      bodyFormat: 'json',
      client: client('post'),
      authorize: {
        url: 'https://auth.atlassian.com/authorize',
        scope: 'offline_access read:jira-work',
        params: { audience: 'api.atlassian.com', prompt: 'consent' },
      },
    },
    note: 'token 请求用 JSON 体：官方文档只给了 JSON 的写法。',
    source: ['https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/'],
    checked,
  },
  {
    id: 'xero',
    label: 'Xero',
    origin: 'https://api.xero.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://identity.xero.com/connect/token',
      client: client('basic'),
      authorize: {
        url: 'https://login.xero.com/identity/connect/authorize',
        scope: 'offline_access accounting.transactions',
      },
    },
    source: ['https://developer.xero.com/faq/oauth2', 'https://identity.xero.com/.well-known/openid-configuration'],
    checked,
  },
  {
    id: 'linear',
    label: 'Linear',
    origin: 'https://api.linear.app',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://api.linear.app/oauth/token',
      client: client('post'),
      authorize: { url: 'https://linear.app/oauth/authorize', scope: 'read,write' },
    },
    note: 'Linear 的 scope 用逗号分隔。',
    source: ['https://linear.app/developers/oauth-2-0-authentication'],
    checked,
  },
  {
    id: 'notion',
    label: 'Notion',
    origin: 'https://api.notion.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://api.notion.com/v1/oauth/token',
      bodyFormat: 'json',
      client: client('basic'),
      ttl: 3600,
      authorize: { url: 'https://api.notion.com/v1/oauth/authorize', params: { owner: 'user' } },
    },
    note: 'Notion 没有 scope；token 端点的回复没有有效期，所以填了 ttl。每个请求要带 Notion-Version 头，写进给 Agent 的说明。',
    source: [
      'https://developers.notion.com/docs/authorization',
      'https://developers.notion.com/reference/create-a-token',
    ],
    checked,
  },
  {
    id: 'x',
    label: 'X',
    origin: 'https://api.x.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://api.x.com/2/oauth2/token',
      client: client('basic'),
      authorize: { url: 'https://x.com/i/oauth2/authorize', scope: 'tweet.read users.read offline.access' },
    },
    source: ['https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code'],
    checked,
  },
  {
    id: 'github-app-user',
    label: 'GitHub App 用户 token',
    origin: 'https://api.github.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://github.com/login/oauth/access_token',
      client: client('post'),
      authorize: { url: 'https://github.com/login/oauth/authorize' },
    },
    note: 'GitHub App 的设置里要开启 User-to-server token expiration，否则拿不到 refresh token。',
    source: [
      'https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app',
      'https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens',
    ],
    checked,
  },
  {
    id: 'dropbox',
    label: 'Dropbox',
    origin: 'https://api.dropboxapi.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://api.dropboxapi.com/oauth2/token',
      client: client('post'),
      authorize: { url: 'https://www.dropbox.com/oauth2/authorize', params: { token_access_type: 'offline' } },
    },
    source: ['https://docs.dropboxapi.com/dropbox-api/docs/oauth'],
    checked,
  },
  {
    id: 'spotify-user',
    label: 'Spotify 用户授权',
    origin: 'https://api.spotify.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://accounts.spotify.com/api/token',
      client: client('basic'),
      authorize: { url: 'https://accounts.spotify.com/authorize', scope: 'user-read-private' },
    },
    source: ['https://developer.spotify.com/documentation/web-api/tutorials/code-flow'],
    checked,
  },
  {
    id: 'salesforce-user',
    label: 'Salesforce 用户授权',
    origin: 'https://{mydomain}.my.salesforce.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://{mydomain}.my.salesforce.com/services/oauth2/token',
      client: client('post'),
      ttl: 3600,
      authorize: { url: 'https://{mydomain}.my.salesforce.com/services/oauth2/authorize', scope: 'api refresh_token' },
    },
    note: 'token 端点的回复没有有效期，ttl 按组织的会话超时填。服务地址用 My Domain 主机，不用回复里的 instance_url。',
    source: ['https://help.salesforce.com/s/articleView?id=remoteaccess_oauth_web_server_flow.htm'],
    checked,
  },
  {
    id: 'zoom-user',
    label: 'Zoom 用户授权',
    origin: 'https://api.zoom.us',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://zoom.us/oauth/token',
      client: client('basic'),
      authorize: { url: 'https://zoom.us/oauth/authorize' },
    },
    note: 'Zoom 的 scope 在应用里配置，授权请求不带。',
    source: ['https://developers.zoom.us/docs/integrations/oauth/'],
    checked,
  },
  {
    id: 'hubspot',
    label: 'HubSpot',
    origin: 'https://api.hubapi.com',
    auth: {
      type: 'oauth-refresh',
      ...refresh,
      tokenUrl: 'https://api.hubapi.com/oauth/v3/token',
      client: client('post'),
      authorize: { url: 'https://app.hubspot.com/oauth/authorize', scope: 'oauth crm.objects.contacts.read' },
    },
    source: ['https://developers.hubspot.com/docs/api-reference/legacy/authentication/manage-oauth-tokens'],
    checked,
  },
];

/** The placeholders in a value (a preset's origin and auth, or what the form made of them), each once.
 * A field reference {"$field": …} is never one. */
export const placeholders = (value: unknown) => [
  ...new Set([...JSON.stringify(value).matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1])),
];
