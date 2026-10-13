import { oauthProvider, oauthDeviceAuthorization } from '@better-auth/oauth-provider';
import { passkey } from '@better-auth/passkey';
import { jwt } from 'better-auth/plugins';
export const OWNER = 'owner';
export const SCOPES = ['offline_access', 'metadata:list', 'secret:read', 'connection:invoke', 'access:request'];
export const tokenHash = async (token: string) => {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Buffer.from(bytes).toString('base64url');
};
export function authPlugins(origin: string, ownerId = OWNER) {
  return [
    jwt(),
    passkey({ rpID: new URL(origin).hostname, rpName: 'Clavifer', origin }),
    oauthProvider({
      // The API takes a JWT access token issued for the one resource below. The Worker verifies its
      // signature against its own key set and looks up the client on every request (principal in
      // context.ts), so a revoked installation is refused at once, not when the token expires.
      loginPage: '/login',
      consentPage: '/consent',
      scopes: SCOPES,
      accessTokenExpiresIn: 600,
      refreshTokenExpiresIn: 90 * 86400,
      refreshTokenReuseInterval: 20,
      codeExpiresIn: 120,
      storeTokens: { hash: tokenHash },
      grantTypes: ['authorization_code', 'refresh_token'],
      resources: [`${origin}/v1`],
      clientRegistrationDefaultResources: [`${origin}/v1`],
      // One resource and one audience, with every client created by the Owner: the per-client link
      // adds no isolation over the grants table, and it silently strands every installation when
      // the origin changes, because the link records the resource URI of the day it was created.
      enforcePerClientResources: false,
      allowDynamicClientRegistration: false,
      allowUnauthenticatedClientRegistration: false,
      clientPrivileges: ({ user }) => user?.id === ownerId,
      resourcePrivileges: () => false,
    }),
    oauthDeviceAuthorization({ verificationUri: `${origin}/device` }),
  ];
}
export const emailPassword = {
  enabled: true,
  requireEmailVerification: false,
  autoSignIn: true,
  minPasswordLength: 12,
};
export const additionalSessionFields = {
  encryptedToken: { type: 'string' as const, required: false, returned: false, input: false },
  bootstrap: { type: 'boolean' as const, defaultValue: false, returned: false, input: false },
};
