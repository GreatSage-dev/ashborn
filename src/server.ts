import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { AshbornEngine } from './engine.js';
import { CurlParser } from './scout/curl_parser.js';
import { CdpAutopilot, CdpScout, launchDebugChrome } from './scout/cdp_scout.js';
import { TargetLedger } from './storage/target_ledger.js';
import { TargetScope, DualSessionContext } from './types.js';
import { runGroundTruthBenchmark } from './benchmark/benchmark_runner.js';
import { COCKPIT_HTML } from './cockpit_html.js';
import { CopilotEngine, COPILOT_PROVIDER_PRESETS, CopilotMessage, CopilotProvider, CopilotSecurityContext } from './copilot/copilot_engine.js';

const PORT = 3000;
const engine = new AshbornEngine({ enableHaddixMatrix: true });
const ledger = new TargetLedger();
const autopilot = new CdpAutopilot();
const copilotEngine = new CopilotEngine();

function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      if (!body.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body) as Record<string, unknown>);
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', err => reject(err));
  });
}

function sendJson(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const DEMO_VICTIM_ID = 'rec_octane_881';
const DEMO_VICTIM_SECRET = 'CONFIDENTIAL_CUSTOMER_DATA_778192_LEAKED';
const DEMO_ATTACKER_TOKEN = 'ashborn_hunter_token_session_b';

export async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  // CORS, Chrome Private Network Access & Security headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Private-Network', 'true');

  const method = req.method || 'GET';
  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Extract path, handling Vercel rewrites & query params
  const rawUrl = req.url || '/';
  let pathname = '/';
  try {
    const parsed = new URL(rawUrl, 'http://127.0.0.1');
    const pathParam = parsed.searchParams.get('path') || parsed.searchParams.get('__route');
    if (pathParam) {
      pathname = pathParam.startsWith('/api')
        ? pathParam
        : `/api/${pathParam.replace(/^\/+/, '')}`;
    } else if (req.headers['x-matched-path'] && req.headers['x-matched-path'] !== '/api/index.js') {
      pathname = req.headers['x-matched-path'] as string;
    } else {
      pathname = parsed.pathname;
    }
  } catch {
    pathname = rawUrl;
  }

  // Strip query string if any remains
  pathname = pathname.split('?')[0];

  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.slice(0, -1);
  }

  // 1. Static File Serving (Landing Page & Dashboard)
  if ((method === 'GET' || method === 'HEAD') && (pathname === '/' || pathname === '/index.html')) {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=0, must-revalidate',
    });
    if (method === 'HEAD') {
      res.end();
      return;
    }
    const indexPath = join(process.cwd(), 'public', 'index.html');
    if (existsSync(indexPath)) {
      try {
        res.end(readFileSync(indexPath, 'utf-8'));
        return;
      } catch {}
    }
    res.end(COCKPIT_HTML);
    return;
  }

  // 2. Demo Vulnerable & Secure API Endpoints (Built-in live testbed)
  if (pathname.startsWith('/api/demo/workspaces/')) {
    if (method !== 'GET') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Method Not Allowed' }));
      return;
    }
    const auth = req.headers['authorization'] || '';
    if (
      auth.includes(DEMO_ATTACKER_TOKEN) ||
      auth.includes('token_victim_user_a') ||
      auth.includes('token_user_a')
    ) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        workspaceId: DEMO_VICTIM_ID,
        owner: 'Victim Executive',
        confidentialSnippet: DEMO_VICTIM_SECRET,
        activeSeats: 120,
      }));
      return;
    }
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  if (pathname.startsWith('/api/demo/users/') && method === 'PUT') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'updated',
          userId: DEMO_VICTIM_ID,
          role: parsed.role || 'user',
          isAdmin: parsed.isAdmin || false,
        }));
      } catch {
        res.writeHead(400);
        res.end();
      }
    });
    return;
  }

  if (pathname.startsWith('/api/demo/secure_profile/')) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Forbidden: Cross-tenant isolation enforced.' }));
    return;
  }

  if (pathname.startsWith('/api/demo/billing/')) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Billing operations require elevated administrative context.' }));
    return;
  }

  // 3. Ground-Truth Adversarial Benchmark API Endpoint
  if (pathname === '/api/benchmark' && method === 'GET') {
    try {
      const scorecard = await runGroundTruthBenchmark(0);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(scorecard));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    }
    return;
  }

  // 4. Target Ledger: List Tracked Targets
  if (pathname === '/api/targets' && method === 'GET') {
    try {
      const targets = ledger.listTargets();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ targets }));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    }
    return;
  }

  // 5. Ingress: Audit via Raw Browser / Burp Suite cURL Commands
  if (pathname === '/api/audit/curl' && method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        if (!payload.userACurl || !payload.userBCurl) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Both userACurl and userBCurl are required for dual-session testing.' }));
          return;
        }

        const { primaryCurl, attackerCurl } = CurlParser.buildDualContextFromCurls(
          payload.userACurl,
          payload.userBCurl
        );

        const describeAuth = (parsed: typeof primaryCurl) => {
          if (parsed.headers['authorization']) return 'Authorization Header';
          const cookieCount = Object.keys(parsed.cookies).length;
          if (cookieCount > 0) {
            return `Cookies (${cookieCount})${parsed.csrfToken ? ' + CSRF Token' : ''}`;
          }
          return 'Unauthenticated';
        };

        const result = await engine.auditTargetWithCurls(
          payload.userACurl,
          payload.userBCurl,
          payload.programName
        );

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ...result,
          ingressSummary: {
            targetUrl: primaryCurl.rawUrl,
            method: primaryCurl.method,
            extractedResourceId: primaryCurl.extractedResourceId || null,
            victimAuthMode: describeAuth(primaryCurl),
            attackerAuthMode: describeAuth(attackerCurl),
          },
        }));
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        const isClientValidationError =
          /Invalid cURL|Invalid URL|Identical session credentials|Unexpected token/i.test(message);
        res.writeHead(isClientValidationError ? 400 : 500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: message }));
      }
    });
    return;
  }

  // 6. Chrome DevTools Protocol (CDP) Autonomous Auto-Pilot Endpoints
  if (pathname.startsWith('/api/autopilot/') && process.env.VERCEL) {
    return sendJson(res, 400, {
      error: 'Chrome Auto-Pilot requires the local Ashborn bridge running on http://127.0.0.1:3000 (run "npm start" on your PC).',
      connected: false,
      serverless: true,
    });
  }

  if (pathname === '/api/autopilot/status' && method === 'GET') {
    return sendJson(res, 200, autopilot.getStatus());
  }

  if (pathname === '/api/autopilot/targets' && method === 'GET') {
    try {
      const parsed = new URL(rawUrl, 'http://127.0.0.1');
      const cdpUrl = parsed.searchParams.get('cdpUrl') || 'http://127.0.0.1:9222';
      const targets = await CdpScout.listTargets(cdpUrl);
      return sendJson(res, 200, { targets });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return sendJson(res, 400, { error: message, targets: [] });
    }
  }

  if (pathname === '/api/autopilot/launch-chrome' && method === 'POST') {
    try {
      const payload = await readJsonBody(req);
      const targetUrl = typeof payload.targetUrl === 'string' && payload.targetUrl ? payload.targetUrl : 'https://white.market';
      const port = typeof payload.port === 'number' ? payload.port : 9222;
      const launchRes = await launchDebugChrome(targetUrl, port);
      return sendJson(res, 200, launchRes);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return sendJson(res, 500, { error: message });
    }
  }

  if (pathname === '/api/autopilot/attacker' && method === 'POST') {
    try {
      const payload = await readJsonBody(req);
      if (typeof payload.attackerCurl === 'string' && payload.attackerCurl.trim()) {
        const resObj = autopilot.setAttackerFromCurl(payload.attackerCurl);
        return sendJson(res, 200, { ...resObj, status: autopilot.getStatus() });
      }
      if (typeof payload.targetId === 'string' && payload.targetId.trim()) {
        const cdpHttpUrl = typeof payload.cdpHttpUrl === 'string' ? payload.cdpHttpUrl : 'http://127.0.0.1:9222';
        const resObj = await autopilot.captureAttackerFromTab(cdpHttpUrl, payload.targetId);
        return sendJson(res, 200, { ...resObj, status: autopilot.getStatus() });
      }
      return sendJson(res, 400, { error: 'Provide either attackerCurl or targetId to capture Account B session.' });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return sendJson(res, 400, { error: message });
    }
  }

  if (pathname === '/api/autopilot/guest-attacker' && method === 'POST') {
    try {
      const resObj = autopilot.setAttackerAsGuest();
      return sendJson(res, 200, { ...resObj, status: autopilot.getStatus() });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return sendJson(res, 400, { error: message });
    }
  }

  if (pathname === '/api/autopilot/open-tab' && method === 'POST') {
    try {
      const payload = await readJsonBody(req);
      const urlToOpen = typeof payload.url === 'string' && payload.url.trim() ? payload.url.trim() : 'https://white.market';
      const cdpHttpUrl = typeof payload.cdpHttpUrl === 'string' ? payload.cdpHttpUrl : 'http://127.0.0.1:9222';
      const newTabRes = await fetch(`${cdpHttpUrl}/json/new?${encodeURIComponent(urlToOpen)}`, { method: 'PUT' });
      const newTab = await newTabRes.json();
      return sendJson(res, 200, { tab: newTab });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return sendJson(res, 400, { error: message });
    }
  }

  if (pathname === '/api/autopilot/connect' && method === 'POST') {
    try {
      const payload = await readJsonBody(req);
      const allowedHosts = Array.isArray(payload.allowedHosts)
        ? payload.allowedHosts.map(String).filter(Boolean)
        : typeof payload.allowedHosts === 'string'
        ? payload.allowedHosts.split(',').map(s => s.trim()).filter(Boolean)
        : undefined;

      const status = await autopilot.connect({
        cdpHttpUrl: typeof payload.cdpHttpUrl === 'string' ? payload.cdpHttpUrl : 'http://127.0.0.1:9222',
        targetId: typeof payload.targetId === 'string' ? payload.targetId : undefined,
        allowedHosts,
        programName: typeof payload.programName === 'string' ? payload.programName : undefined,
        readOnlySafeMode: typeof payload.readOnlySafeMode === 'boolean' ? payload.readOnlySafeMode : true,
      });
      return sendJson(res, 200, status);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return sendJson(res, 400, { error: message });
    }
  }

  if (pathname === '/api/autopilot/disconnect' && method === 'POST') {
    await autopilot.disconnect();
    return sendJson(res, 200, autopilot.getStatus());
  }

  if (pathname === '/api/autopilot/clear' && method === 'POST') {
    autopilot.clearSessionResults();
    return sendJson(res, 200, autopilot.getStatus());
  }

  if (pathname === '/api/autopilot/mode' && method === 'POST') {
    try {
      const payload = await readJsonBody(req);
      autopilot.setReadOnlySafeMode(Boolean(payload.readOnlySafeMode));
      return sendJson(res, 200, autopilot.getStatus());
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return sendJson(res, 400, { error: message });
    }
  }

  if (pathname === '/api/autopilot/strike' && method === 'POST') {
    try {
      const payload = await readJsonBody(req);
      if (typeof payload.capturedId !== 'string') {
        return sendJson(res, 400, { error: 'capturedId is required.' });
      }
      const item = await autopilot.strikeCapturedById(
        payload.capturedId,
        payload.allowMutations !== undefined ? Boolean(payload.allowMutations) : true
      );
      return sendJson(res, 200, { item, status: autopilot.getStatus() });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return sendJson(res, 400, { error: message });
    }
  }

  // 6b. Shadow Co-Pilot AI Pair-Hunting Endpoints (BYOK / Free LLM APIs / Built-in Engine)
  if (pathname === '/api/copilot/presets' && method === 'GET') {
    return sendJson(res, 200, { presets: COPILOT_PROVIDER_PRESETS });
  }

  if (pathname === '/api/copilot/chat' && method === 'POST') {
    try {
      const payload = await readJsonBody(req);
      const messages = Array.isArray(payload.messages) ? (payload.messages as CopilotMessage[]) : [];
      const provider = (typeof payload.provider === 'string' ? payload.provider : 'builtin') as CopilotProvider;
      const apiKey = typeof payload.apiKey === 'string' ? payload.apiKey.trim() : undefined;
      const model = typeof payload.model === 'string' ? payload.model.trim() : undefined;
      const customEndpoint = typeof payload.customEndpoint === 'string' ? payload.customEndpoint.trim() : undefined;

      const autopilotStatus = autopilot.getStatus();
      const securityContext: CopilotSecurityContext = {
        targetUrl: autopilotStatus.targetUrl || 'https://white.market',
        allowedHosts: autopilotStatus.allowedHosts.length > 0 ? autopilotStatus.allowedHosts : ['white.market', '*.white.market'],
        readOnlySafeMode: autopilotStatus.readOnlySafeMode,
        attackerAuthSummary: autopilotStatus.attackerAuthSummary,
        capturedEndpoints: autopilotStatus.capturedEndpoints,
        receipts: autopilotStatus.receipts,
        reports: autopilotStatus.reports,
        logs: autopilotStatus.logs,
      };

      const response = await copilotEngine.chat(messages, securityContext, {
        provider,
        apiKey,
        model,
        customEndpoint,
      });

      return sendJson(res, 200, response);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return sendJson(res, 500, { error: message });
    }
  }

  // 7. Ashborn Bundle & OpenAPI Audit Endpoint
  if (pathname === '/api/audit' && method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const host = req.headers.host || `127.0.0.1:${PORT}`;
        const protocol = req.headers['x-forwarded-proto'] || 'http';
        const defaultBaseUrl = `${protocol}://${host}`;
        const baseUrl = payload.scope?.baseUrl || defaultBaseUrl;
        let parsedHost = '127.0.0.1';
        try {
          parsedHost = new URL(baseUrl).hostname;
        } catch {}

        const allowedHosts = payload.scope?.allowedHosts && payload.scope.allowedHosts.length > 0
          ? payload.scope.allowedHosts
          : [parsedHost, '127.0.0.1', 'localhost'];

        const scope: TargetScope = {
          name: payload.scope?.name || 'Target App',
          baseUrl,
          allowedHosts,
          rulesOfEngagement: payload.scope?.rulesOfEngagement || 'Authorized security assessment',
        };

        const context: DualSessionContext = payload.context || {
          victimToken: 'token_user_a',
          victimResourceId: DEMO_VICTIM_ID,
          victimSecretIdentifier: DEMO_VICTIM_SECRET,
          attackerToken: DEMO_ATTACKER_TOKEN,
        };

        let result;
        if (payload.openApiSchema) {
          result = await engine.auditTargetWithOpenApi(scope, payload.openApiSchema, context);
        } else {
          const sampleBundle = payload.bundleContent || `
            const routes = [
              "/api/demo/workspaces/:workspace_id",
              "/api/demo/users/{id}",
              "/api/demo/secure_profile/:id",
              "/api/demo/billing/users/{id}/charge"
            ];
          `;
          result = await engine.auditTargetWithBundles(scope, [sampleBundle], context);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: message }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not Found' }));
}

export const server = createServer(handleRequest);
export default handleRequest;

// Auto-start only when executed directly via node dist/server.js or npm run serve
const isDirectRun = Boolean(
  process.argv[1] &&
  (process.argv[1].endsWith('server.js') || process.argv[1].endsWith('server.ts'))
);

if (isDirectRun && !process.env.VERCEL) {
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`\n👑 ASHBORN COCKPIT READY: http://127.0.0.1:${PORT}\n`);
  });
}
