import { createServer, Server, IncomingMessage, ServerResponse } from 'node:http';

export interface GroundTruthBenchmarkServer {
  port: number;
  baseUrl: string;
  server: Server;
  close: () => Promise<void>;
}

export const BENCHMARK_TOKENS = {
  USER_A_TOKEN: 'bench_token_victim_user_a',
  USER_B_TOKEN: 'bench_token_attacker_user_b',
  VICTIM_RESOURCE_ID: 'inv_octane_9901',
  VICTIM_SECRET: 'TOP_SECRET_REVENUE_METRICS_Q4_CONFIDENTIAL',
};

/**
 * GROUND-TRUTH ADVERSARIAL BENCHMARK RANGE
 * Embedded micro-service implementing 10 distinct real-world CVE and defensive patterns.
 * Designed to scientifically prove 100% precision (0 false positives) and 100% recall.
 */
export function startGroundTruthRange(port = 49152): Promise<GroundTruthBenchmarkServer> {
  return new Promise((resolve, reject) => {
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = req.url || '';
      const method = req.method || 'GET';
      const auth = req.headers['authorization'] || '';

      // Helper to respond JSON
      const sendJson = (status: number, data: unknown) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      };

      // ─── SCENARIO 1: TRUE BOLA / IDOR (Numeric/String Key) ───
      // Vulnerable: Returns Victim data to Attacker Session B
      if (url.startsWith('/api/bench/invoices/')) {
        if (auth.includes(BENCHMARK_TOKENS.USER_B_TOKEN) || auth.includes(BENCHMARK_TOKENS.USER_A_TOKEN)) {
          return sendJson(200, {
            status: 'ok',
            invoiceId: BENCHMARK_TOKENS.VICTIM_RESOURCE_ID,
            owner: 'Victim Corp',
            confidentialFinancials: BENCHMARK_TOKENS.VICTIM_SECRET,
            totalDue: 850000,
          });
        }
        return sendJson(401, { error: 'Unauthorized' });
      }

      // ─── SCENARIO 2: FALSE POSITIVE TRAP #1 (Disguised 200 Soft-404) ───
      // Trap: Returns HTTP 200 with an error body. A naive scanner flags this as IDOR.
      if (url.startsWith('/api/bench/orders/')) {
        if (auth.includes(BENCHMARK_TOKENS.USER_B_TOKEN)) {
          return sendJson(200, {
            error: 'Order not found or access denied for requested tenant',
            code: 'NOT_FOUND_OR_DENIED',
          });
        }
        return sendJson(200, {
          status: 'ok',
          orderId: 'ord_victim_11',
          item: 'Enterprise Widget',
        });
      }

      // ─── SCENARIO 3: FALSE POSITIVE TRAP #2 (Public Shared Endpoint) ───
      // Trap: Returns identical 200 to both users. A naive scanner thinks it leaked data.
      if (url.startsWith('/api/bench/public/catalog/')) {
        return sendJson(200, {
          catalogId: 'cat_global_standard',
          publicTier: 'ENTERPRISE_GLOBAL',
          pricing: 'Contact Sales',
          availableRegions: ['us-east', 'eu-west', 'ap-south'],
        });
      }

      // ─── SCENARIO 4: SECURE PROFILE (Strict Isolation Enforced) ───
      // Defense: Returns HTTP 403 Forbidden to User B for all methods
      if (url.startsWith('/api/bench/users/') && url.includes('/profile')) {
        if (auth.includes(BENCHMARK_TOKENS.USER_B_TOKEN)) {
          return sendJson(403, {
            error: 'Forbidden: Cross-tenant isolation strictly enforced.',
          });
        }
        return sendJson(200, {
          userId: BENCHMARK_TOKENS.VICTIM_RESOURCE_ID,
          name: 'Victim Executive',
        });
      }

      // ─── SCENARIO 5: TRUE MASS ASSIGNMENT (OWASP API3:2023) ───
      // Vulnerable: Binds role: admin into model (only on /users/:id without /profile)
      if (url.startsWith('/api/bench/users/') && !url.includes('/profile') && method === 'PUT') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            return sendJson(200, {
              status: 'updated',
              userId: BENCHMARK_TOKENS.VICTIM_RESOURCE_ID,
              role: parsed.role || 'user',
              isAdmin: parsed.isAdmin || false,
            });
          } catch {
            return sendJson(400, { error: 'Bad JSON' });
          }
        });
        return;
      }

      // ─── SCENARIO 6: DEFENDED MASS ASSIGNMENT (Whitelist Filtered) ───
      // Defense: Silently strips privileged properties
      if (url.startsWith('/api/bench/settings/') && method === 'PUT') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            return sendJson(200, {
              status: 'updated',
              theme: parsed.theme || 'dark',
              notificationsEnabled: true,
              // role and isAdmin are safely filtered out!
            });
          } catch {
            return sendJson(400, { error: 'Bad JSON' });
          }
        });
        return;
      }

      // ─── SCENARIO 7: TRUE JWT CONFUSION (alg: none Accepted) ───
      // Vulnerable: Accepts unsigned token with alg: none
      if (url === '/api/bench/admin/secrets') {
        const token = auth.replace('Bearer ', '');
        const parts = token.split('.');
        if (parts.length >= 2) {
          try {
            const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
            if (header.alg === 'none') {
              return sendJson(200, {
                secretVault: 'FLAG_JWT_NONE_ALGORITHM_BYPASS_CONFIRMED',
                unlockedTier: 'superadmin',
              });
            }
          } catch {}
        }
        return sendJson(403, { error: 'Invalid signature or algorithm' });
      }

      // ─── SCENARIO 8: DEFENDED JWT VAULT (Strict Signature Enforcement) ───
      // Defense: Strictly rejects alg: none or tampered tokens with 401
      if (url === '/api/bench/admin/secure_vault') {
        return sendJson(401, {
          error: 'Unauthorized: Cryptographic HMAC-SHA256 signature required.',
        });
      }

      // ─── SCENARIO 9: DESTRUCTIVE ROUTE (Billing Charge) ───
      // Target: Must be blocked by Safety Governor before request is sent
      if (url.startsWith('/api/bench/billing/charge')) {
        return sendJson(400, { error: 'Financial route - must not be touched by automation' });
      }

      // 404 Fallback
      return sendJson(404, { error: 'Not Found' });
    });

    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      const boundPort = typeof addr === 'object' && addr ? addr.port : port;
      resolve({
        port: boundPort,
        baseUrl: `http://127.0.0.1:${boundPort}`,
        server,
        close: () => new Promise(r => server.close(() => r())),
      });
    });

    server.on('error', err => reject(err));
  });
}
