import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { AshbornEngine } from './engine.js';
import { TargetLedger } from './storage/target_ledger.js';
import { TargetScope, DualSessionContext } from './types.js';
import { runGroundTruthBenchmark } from './benchmark/benchmark_runner.js';
import { COCKPIT_HTML } from './cockpit_html.js';

const PORT = 3000;
const engine = new AshbornEngine({ enableHaddixMatrix: true });
const ledger = new TargetLedger();

const DEMO_VICTIM_ID = 'rec_octane_881';
const DEMO_VICTIM_SECRET = 'CONFIDENTIAL_CUSTOMER_DATA_778192_LEAKED';
const DEMO_ATTACKER_TOKEN = 'ashborn_hunter_token_session_b';

export async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  // CORS & Security headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

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
  if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=0, must-revalidate',
    });
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
    const auth = req.headers['authorization'] || '';
    if (auth.includes(DEMO_ATTACKER_TOKEN)) {
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

        const result = await engine.auditTargetWithCurls(
          payload.userACurl,
          payload.userBCurl,
          payload.programName
        );

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

  // 6. Ashborn Bundle & OpenAPI Audit Endpoint
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
