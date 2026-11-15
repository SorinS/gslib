// node-oidc-provider configured for goose-oauth's interop tests
// (oauth/scripts/interop.py), on https://localhost:PORT with a test CA's
// certificate, asking for client certificates (mutual TLS) but not
// requiring them.
//
//   node provider.mjs config.json
//
// config.json (written by interop.py): port, the TLS files (key, cert, ca),
// the client secrets, and where to write the private_key_jwt client's
// private JWK. Prints "listening on <issuer>" when ready.
//
// Logins and consents need no browser: /interaction/:uid signs "alice" in
// and grants what the client asked for, then hands back to the provider.
// Token exchange (RFC 8693) is not built into oidc-provider: a minimal
// grant is registered below, which takes a valid access token and issues
// a new one to the calling client.

import fs from 'node:fs';
import https from 'node:https';
import crypto from 'node:crypto';
import Provider, { errors } from 'oidc-provider';

const cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const issuer = `https://localhost:${cfg.port}`;

function keypair(type, opts, kid, alg) {
  const { privateKey } = crypto.generateKeyPairSync(type, opts);
  return { ...privateKey.export({ format: 'jwk' }), kid, alg, use: 'sig' };
}
const signing = [
  keypair('rsa', { modulusLength: 2048 }, 'op-rsa-1', 'RS256'),
  keypair('ec', { namedCurve: 'P-256' }, 'op-ec-1', 'ES256'),
];
const clientKey = keypair('ec', { namedCurve: 'P-256' }, 'client-ec-1', 'ES256');
fs.writeFileSync(cfg.client_key_out, JSON.stringify(clientKey), { mode: 0o600 });
const { d, ...clientPub } = clientKey;

const API = 'urn:example:api';
const SCOPE = 'openid profile email offline_access api:read api:write';
const GRANTS = ['client_credentials', 'authorization_code', 'refresh_token',
  'urn:ietf:params:oauth:grant-type:device_code', 'urn:ietf:params:oauth:grant-type:token-exchange'];
const common = {
  grant_types: GRANTS, response_types: ['code'], application_type: 'native',
  redirect_uris: ['http://127.0.0.1/callback'], scope: SCOPE,
};

const pem = (raw) => `-----BEGIN CERTIFICATE-----\n${raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
const peer = (ctx) => {
  const c = ctx.socket && ctx.socket.getPeerCertificate ? ctx.socket.getPeerCertificate() : null;
  return c && c.raw ? c : null;
};

const configuration = {
  clients: [
    { ...common, client_id: 'basic-client', client_secret: cfg.secrets.basic, token_endpoint_auth_method: 'client_secret_basic' },
    { ...common, client_id: 'post-client', client_secret: cfg.secrets.post, token_endpoint_auth_method: 'client_secret_post',
      userinfo_signed_response_alg: 'RS256' },
    { ...common, client_id: 'jwt-client', token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [clientPub] } },
    { ...common, client_id: 'mtls-client', token_endpoint_auth_method: 'tls_client_auth',
      tls_client_auth_subject_dn: 'CN=mtls-client', tls_client_certificate_bound_access_tokens: true },
    { ...common, client_id: 'public-client', token_endpoint_auth_method: 'none' },
    { ...common, client_id: 'dpop-client', client_secret: cfg.secrets.dpop, token_endpoint_auth_method: 'client_secret_basic',
      dpop_bound_access_tokens: true },
  ],
  jwks: { keys: signing },
  clientAuthMethods: ['none', 'client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt', 'tls_client_auth'],
  cookies: { keys: [crypto.randomBytes(32).toString('hex')] },
  scopes: ['openid', 'profile', 'email', 'offline_access', 'api:read', 'api:write'],
  claims: { openid: ['sub'], email: ['email', 'email_verified'], profile: ['name'] },
  findAccount: async (ctx, id) => ({
    accountId: id,
    claims: async () => ({ sub: id, email: `${id}@example.test`, email_verified: true, name: 'Alice Example' }),
  }),
  interactions: { url: (ctx, interaction) => `/interaction/${interaction.uid}` },
  issueRefreshToken: async (ctx, client, code) => client.grantTypeAllowed('refresh_token'),
  features: {
    devInteractions: { enabled: false },
    clientCredentials: { enabled: true },
    deviceFlow: { enabled: true },
    introspection: { enabled: true },
    revocation: { enabled: true },
    pushedAuthorizationRequests: { enabled: true },
    jwtUserinfo: { enabled: true },
    dPoP: { enabled: true, nonceSecret: crypto.randomBytes(32), requireNonce: () => true },
    resourceIndicators: {
      enabled: true,
      defaultResource: () => undefined,
      useGrantedResource: () => true,
      getResourceServerInfo: (ctx, resource) => {
        if (resource !== API) throw new errors.InvalidTarget();
        return { scope: 'api:read api:write', audience: API, accessTokenFormat: 'jwt', jwt: { sign: { alg: 'ES256' } } };
      },
    },
    mTLS: {
      enabled: true,
      certificateBoundAccessTokens: true,
      tlsClientAuth: true,
      getCertificate: (ctx) => { const c = peer(ctx); return c ? pem(c.raw) : undefined; },
      certificateAuthorized: (ctx) => !!(ctx.socket && ctx.socket.authorized),
      certificateSubjectMatches: (ctx, property, expected) => {
        const c = peer(ctx);
        return property === 'tls_client_auth_subject_dn' && !!c && expected === `CN=${c.subject.CN}`;
      },
    },
  },
};

const provider = new Provider(issuer, configuration);

// RFC 8693, minimally: an access token of this provider for a new one.
const TT_AT = 'urn:ietf:params:oauth:token-type:access_token';
provider.registerGrantType('urn:ietf:params:oauth:grant-type:token-exchange', async (ctx) => {
  const { subject_token: st, subject_token_type: stt } = ctx.oidc.params;
  if (!st || stt !== TT_AT) throw new errors.InvalidRequest('subject_token of type access_token required');
  const subject = await ctx.oidc.provider.AccessToken.find(st)
    || await ctx.oidc.provider.ClientCredentials.find(st);
  if (!subject || subject.isExpired) throw new errors.InvalidGrant('the subject token is not valid');
  const at = new ctx.oidc.provider.ClientCredentials({ client: ctx.oidc.client, scope: 'api:read' });
  const value = await at.save();
  ctx.body = { access_token: value, issued_token_type: TT_AT, token_type: 'Bearer', expires_in: at.expiration, scope: 'api:read' };
}, ['subject_token', 'subject_token_type', 'audience', 'resource', 'scope', 'requested_token_type', 'actor_token', 'actor_token_type']);

// Every interaction: alice signs in, and gets what the client asked for.
provider.use(async (ctx, next) => {
  if (!ctx.path.startsWith('/interaction/')) return next();
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  const { prompt, params, session } = details;
  let result;
  if (prompt.name === 'login') {
    result = { login: { accountId: 'alice' } };
  } else {
    const grant = details.grantId ? await provider.Grant.find(details.grantId)
      : new provider.Grant({ accountId: session.accountId, clientId: params.client_id });
    const d = prompt.details || {};
    if (d.missingOIDCScope) grant.addOIDCScope(d.missingOIDCScope.join(' '));
    if (d.missingOIDCClaims) grant.addOIDCClaims(d.missingOIDCClaims);
    if (d.missingResourceScopes) {
      for (const [indicator, scopes] of Object.entries(d.missingResourceScopes)) grant.addResourceScope(indicator, scopes.join(' '));
    }
    result = { consent: { grantId: await grant.save() } };
  }
  ctx.respond = false;
  await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: true });
});

const server = https.createServer({
  key: fs.readFileSync(cfg.key), cert: fs.readFileSync(cfg.cert), ca: fs.readFileSync(cfg.ca),
  requestCert: true, rejectUnauthorized: false,
}, provider.callback());
server.listen(cfg.port, '127.0.0.1', () => { console.log(`listening on ${issuer}`); });
