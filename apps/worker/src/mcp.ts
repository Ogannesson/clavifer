import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { Fault } from '../../../packages/core/errors';
import { type Bindings, type Principal, boundedBytes, issuesHint, readJson } from './context';
import { metadata, accessRequest, accessStatus, invoke, invokeInput, requestInput, resourceId } from './vault';

export async function handleMcp(request: Request, env: Bindings, p: Principal) {
  const server = new Server(
    { name: 'clavifer', version: '0.5.0' },
    {
      capabilities: { tools: {} },
      instructions: [
        'Use credentials.list first: it lists every connection (origin; policy_json with the allowed paths and methods that form its regular scope and its deny / approval / free rules; description with the Owner’s usage notes; whether this installation holds a grant, until when, and its scope extensions) and the secrets granted to this installation with their grant expiry. http.request invokes a fixed connection with server-injected credentials; send the request directly first.',
        'Only a deny rule is an absolute refusal; every other refusal has a way through the Owner. Each error carries a hint. Next step by error:',
        '- path_denied: stop. A deny rule (quoted in the hint) forbids it and only the Owner can lift it by editing the connection. Tell the user which rule; do not request access.',
        '- path_not_allowed / method_not_allowed: outside the regular scope, not forbidden. One operation: access.request with requested.invocation set to this exact request. Multi-step work: access.request with requested.grants for the connection carrying paths and/or methods as a temporary scope extension.',
        '- grant_required: access.request with requested.grants for multi-step work, or requested.invocation for one operation.',
        '- approval_required: access.request with requested.invocation; a grant does not cover this request.',
        '- host_not_allowed: the connection does not list the host of the origin you named. Tell the user which host is needed; the Owner can add it to the connection’s extra hosts. Do not retry with another spelling of the address.',
        '- invalid_path: the path holds a refused character (the hint says which). Do not try other encodings; use an API that takes the key in the body (such as a bulk endpoint) or ask the user to do it manually. %2F and %20 inside a segment are accepted.',
        '- body_too_large / response_too_large: paginate or narrow the query, split writes, upload large files with the host’s own tools.',
        '- connection_not_found: tell the user which connection is needed: origin, authentication, suggested paths, methods and rules. If the user agrees, submit it as a draft with access.request requested.setup (credential field names only, with a test table); never submit one without asking.',
        '- upstream_outcome_unknown: the request may have run. Read the upstream state before deciding; never retry a write automatically.',
        'A request goes to the connection’s own origin. Only when its policy_json lists hosts (extra hosts: a name, or *.suffix for every host below it) or has anyHost true may one request go elsewhere, for example to a download host the API points to: put origin (https://host) in requested.invocation, and after approval resend it through http.request with the same origin. No grant, extension or free rule counts on another origin, and the REST proxy cannot name one.',
        'In reason name the target the way a person knows it (name, account, creation date) and the expected effect; when acting on an opaque id, say how you identified it so the Owner can check it in the upstream console.',
        'Then wait for the Owner. If the access.request result has waitCommand, run it as a shell command (in PowerShell prefix it with "& "): in the background and end your turn where the host notifies you when a background command exits, otherwise in the foreground, which blocks: set the host command timeout no shorter than its --timeout (default 25 minutes), or append a shorter --timeout and rerun after 124. It exits once the Owner decides and prints the final status. approved: resend the identical request with http.request (same method, path, query, headers and body; the REST proxy adds client headers and will not match) or start the granted work, which lasts until each grant’s expires_at in the status (null: until revoked). denied / expired: stop and tell the user. Exit code 124 means still pending: run it again or ask the user. Without waitCommand, check access.status now and then, never in a tight loop.',
        'An invocation approval runs once within 10 minutes and is spent when the request is sent. Never print credentials.',
      ].join('\n'),
    },
  );
  const definitions = [
    {
      name: 'credentials.list',
      description:
        'List every connection and the secrets granted to this installation. A connection has policy_json (allowed paths and methods, the regular scope, plus deny / approval / free rules "METHOD /path"; /* covers sub-paths, * any method, GET also covers HEAD; hosts, the extra hosts a one-time invocation may name in origin, each a hostname or *.suffix for every host below it, and anyHost, true when it may name any public HTTPS origin; absent means none), description (the Owner’s usage notes, such as headers every request needs), granted (this installation holds a grant), expires_at (when that grant ends; null: until revoked) and extensions (its live temporary scope extensions {paths, methods, expiresAt}). A secret has expires_at for its grant the same way. Without a grant only free-rule requests and approved invocations run. Paths may use %2F and %20 inside a segment; literal spaces, ";" and control characters are refused.',
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: { type: 'object' as const, properties: {}, additionalProperties: false },
    },
    {
      name: 'access.request',
      description:
        'Ask the Owner for access; returns a request id and an approval link. requested holds exactly one of: grants (secret:read or connection:invoke for a period, for multi-step work; a connection grant may carry paths (prefixes) and/or methods as a temporary scope extension for requests outside the allowed paths and methods; a list left out is fixed to the connection’s current one on approval); invocation (one exact http.request: connection, method, path, query, headers, body up to 64 KiB, and origin when it goes to another origin that the connection’s hosts or anyHost cover; host_not_allowed otherwise) for a single operation, also outside the regular scope or after approval_required; setup (a draft of a new credential, by field names only, and the 1-20 connections using it, such as one API key for several hosts: secret {name, description, fields}, connections [each as the Owner’s form takes it, with auth naming those fields and no secretId, plus its own tests; it may list hosts but never anyHost, which only the Owner sets]; without secret every auth is none); or update (connection id, changes to name, description, paths, methods, deny, approval or free, never origin or auth, and tests). tests is [{method, path, grant (default false: no grant; true: a grant without extension), expect: run or a refusal code}]; the server runs them on the draft policy (update: also on the current one, for the Owner) and refuses the submission with tests_failed, listing each mismatch (setup: with the connection’s index and name), unless all match. The Owner enters the credential values once when approving a setup, which creates the credential and all its connections together; neither carries a grant. Once approved, access.status of a setup returns connectionIds in the order of connections (and secretId). An approved invocation runs once within 10 minutes, only when resent unchanged through http.request. reason must name the target the way a person knows it (name, account, creation date), how an opaque id was identified, and the expected effect. Do not request after path_denied. The local clavifer bridge adds waitCommand, a shell command that exits once the Owner decides; run it as the server instructions describe instead of polling.',
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
      // The schema of what a caller sends: a field with a default is optional. reason keeps its default
      // for the REST API, but over MCP an Agent always writes one for the Owner.
      inputSchema: { ...z.toJSONSchema(requestInput, { io: 'input' }), required: ['requested', 'reason'] } as {
        type: 'object';
      },
    },
    {
      name: 'access.status',
      description:
        'Read this installation’s access request status: pending, approved, denied, expired, or executed (an approved invocation already ran). expires_at is the decision deadline while pending and the run deadline of an approved invocation. An approved grant request returns grants as they stand now: each with expires_at (null: until revoked; a re-grant only lengthens a grant, so it can be later than the period just approved) and extensions with their own expiresAt; a grant that has since ended is left out. An approved setup also returns connectionIds, in the order of its connections, and, with a credential, secretId. Prefer waitCommand from access.request; without it check occasionally, not in a tight loop.',
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        type: 'object' as const,
        properties: { id: { type: 'string' } },
        required: ['id'],
        additionalProperties: false,
      },
    },
    {
      name: 'http.request',
      description:
        'Invoke a connection; try the request directly first. Inside the allowed paths and methods it runs when a free rule covers it or the installation holds a grant; outside them only through a grant extension that covers it; anywhere when the Owner approved this exact invocation. Errors: path_not_allowed / method_not_allowed (outside the regular scope: request an invocation, or grants with paths / methods for multi-step work), grant_required (request grants or an invocation), approval_required (request an invocation), path_denied (a deny rule forbids it: do not request access, tell the user). origin (https://host, optional) sends the request to another origin than the connection’s own; it runs only when the connection’s hosts or anyHost cover that host (else host_not_allowed: tell the user which host is needed) and the Owner approved this exact invocation with the same origin (else approval_required, whatever grants or free rules exist). Every error has a hint with the next step. After an invocation approval resend the identical request; sending it uses the approval even if the upstream outcome is unknown. body is a UTF-8 string, never a shell command. Max response 1 MiB, timeout 20 seconds, no automatic redirects or retries.',
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
      inputSchema: z.toJSONSchema(invokeInput, { io: 'input' }) as { type: 'object' },
    },
  ];
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: definitions }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      let result: unknown;
      const input = request.params.arguments ?? {};
      switch (request.params.name) {
        case 'credentials.list':
          result = await metadata(env, p);
          break;
        case 'access.request':
          result = await accessRequest(env, p, input, env.APP_ORIGIN);
          break;
        case 'access.status':
          result = await accessStatus(env, p, resourceId.parse(input.id));
          break;
        case 'http.request': {
          const r = await invoke(env, p, invokeInput.parse(input));
          // Tool results are text, so this transport bounds a response at 1 MiB; the REST proxy streams it.
          const body = await boundedBytes(r.body).catch((e) => {
            throw e instanceof Fault && e.code === 'body_too_large'
              ? new Fault(
                  'response_too_large',
                  413,
                  'The response exceeded the 1 MiB tool limit; the upstream request already completed, so do not resend a write. Paginate or narrow the query (filters, fields, page size).',
                )
              : e;
          });
          result = { status: r.status, headers: r.headers, body: new TextDecoder().decode(body) };
          break;
        }
        default:
          throw new Fault('unknown_tool', 404);
      }
      return { content: [{ type: 'text', text: JSON.stringify(result) }] };
    } catch (e) {
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: e instanceof Fault ? e.code : e instanceof z.ZodError ? 'invalid_arguments' : 'internal_error',
              ...(e instanceof Fault && e.message !== e.code
                ? { hint: e.message }
                : e instanceof z.ZodError
                  ? { hint: issuesHint(e) }
                  : {}),
            }),
          },
        ],
      };
    }
  });
  const transport = new WebStandardStreamableHTTPServerTransport({ enableJsonResponse: true });
  await server.connect(transport);
  try {
    return await transport.handleRequest(request, {
      // JSON escaping can grow a 1 MiB body several times, so the message bound leaves room for
      // http.request to refuse an oversized body itself, as a tool error with a hint.
      parsedBody: request.method === 'POST' ? await readJson(request, 8 * 1024 * 1024) : undefined,
    });
  } finally {
    await server.close();
  }
}
