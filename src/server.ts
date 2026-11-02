import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { AshbornEngine } from './engine.js';
import { TargetScope, DualSessionContext } from './types.js';
import { runGroundTruthBenchmark } from './benchmark/benchmark_runner.js';

const PORT = 3000;
const engine = new AshbornEngine();

const DEMO_VICTIM_ID = 'rec_octane_881';
const DEMO_VICTIM_SECRET = 'CONFIDENTIAL_CUSTOMER_DATA_778192_LEAKED';
const DEMO_ATTACKER_TOKEN = 'ashborn_hunter_token_session_b';

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = req.url || '/';
  const method = req.method || 'GET';

  // 1. Static File Serving (Landing Page & Dashboard)
  if (method === 'GET' && (url === '/' || url === '/index.html')) {
    const indexPath = join(process.cwd(), 'public', 'index.html');
    if (existsSync(indexPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(readFileSync(indexPath, 'utf-8'));
      return;
    }
  }

  // 2. Demo Vulnerable & Secure API Endpoints (Built-in live testbed)
  if (url.startsWith('/api/demo/workspaces/')) {
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

  if (url.startsWith('/api/demo/users/') && method === 'PUT') {
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

  if (url.startsWith('/api/demo/secure_profile/')) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Forbidden: Cross-tenant isolation enforced.' }));
    return;
  }

  if (url.startsWith('/api/demo/billing/')) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Billing operations require elevated administrative context.' }));
    return;
  }

  // 3. Ground-Truth Adversarial Benchmark API Endpoint
  if (url === '/api/benchmark' && method === 'GET') {
    try {
      const scorecard = await runGroundTruthBenchmark(49156);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(scorecard));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    }
    return;
  }

  // 4. Ashborn Audit API Endpoint
  if (url === '/api/audit' && method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const baseUrl = payload.scope?.baseUrl || `http://127.0.0.1:${PORT}`;
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

  res.writeHead(404);
  res.end('Not Found');
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n👑 ASHBORN COCKPIT READY: http://127.0.0.1:${PORT}\n`);
});
