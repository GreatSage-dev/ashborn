import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, Server, IncomingMessage, ServerResponse } from 'node:http';

import { 
  BundleExtractor, 
  OpenApiParser,
  JwtMutator, 
  IdorStriker, 
  MassAssignmentStriker,
  SafetyGovernor,
  BlastChamber, 
  ReportGenerator, 
  AshbornEngine,
  DualSessionContext,
  TargetScope
} from './index.js';

describe('ASHBORN AUTONOMOUS HUNTER - SYSTEM TEST SUITE', () => {
  let server: Server;
  const PORT = 38472;
  const BASE_URL = `http://127.0.0.1:${PORT}`;

  const VICTIM_SECRET = 'CONFIDENTIAL_SSN_982-11-4091_ACME_CORP';
  const VICTIM_ID = 'inv_alpha_9918';
  const ATTACKER_TOKEN = 'token_attacker_session_772';

  before((_, done) => {
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = req.url || '';
      const method = req.method || 'GET';
      const auth = req.headers['authorization'] || '';

      // ROUTE 1: Vulnerable IDOR Endpoint
      if (url.startsWith('/api/v1/invoices/') || url.includes('/api/v1/invoices?id=')) {
        if (auth.startsWith('Bearer ')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            invoiceId: VICTIM_ID,
            owner: 'Victim User',
            confidentialPayload: VICTIM_SECRET,
            amount: 450000,
          }));
          return;
        }
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      // ROUTE 2: Secure Profile Endpoint (Properly enforced authorization)
      if (url.startsWith('/api/v1/users/') && url.includes('/profile') && method === 'GET') {
        if (auth.includes(ATTACKER_TOKEN)) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Forbidden: You do not own this profile.' }));
          return;
        }
      }

      // ROUTE 3: Vulnerable Mass Assignment Endpoint (PUT)
      if (url.startsWith('/api/v1/users/') && method === 'PUT') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            // Vulnerable backend: blindly reflects updated fields back
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              status: 'updated',
              userId: VICTIM_ID,
              role: parsed.role || 'user',
              isAdmin: parsed.isAdmin || false
            }));
          } catch {
            res.writeHead(400);
            res.end();
          }
        });
        return;
      }

      // ROUTE 4: Vulnerable JWT endpoint
      if (url === '/api/v1/admin/secrets') {
        const token = auth.replace('Bearer ', '');
        const parts = token.split('.');
        if (parts.length >= 2) {
          const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
          if (header.alg === 'none') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ secret: 'ADMIN_FLAG_LEAKED_VIA_NONE_ALG' }));
            return;
          }
        }
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid signature' }));
        return;
      }

      res.writeHead(404);
      res.end('Not Found');
    });

    server.listen(PORT, '127.0.0.1', () => done());
  });

  after((_, done) => {
    server.close(() => done());
  });

  test('Module 1: BundleExtractor pulls API routes from raw JS in <5ms', () => {
    const mockWebpackBundle = `
      var e = function() {
        fetch("/api/v1/invoices/:id", { method: "GET" });
        var u = "/api/v1/users/{user_id}/profile";
        var staticAsset = "/api/static/logo.png";
        var ignored = "/home/landing";
        var mutation = "/api/v1/invoices/cancel";
      };
    `;

    const endpoints = BundleExtractor.extractEndpoints(mockWebpackBundle, 'app.chunk.js');
    assert.strictEqual(endpoints.length, 3);

    const highValue = BundleExtractor.filterHighValueTargets(endpoints);
    assert.strictEqual(highValue.length, 2);
    assert.ok(highValue.some(ep => ep.path === '/api/v1/invoices/:id'));
  });

  test('Upgrade 1: SafetyGovernor strictly blocks destructive & billing paths', () => {
    const safeCheck = SafetyGovernor.isBlocked('/api/v1/invoices/:id', 'GET');
    assert.strictEqual(safeCheck.blocked, false);

    const deleteCheck = SafetyGovernor.isBlocked('/api/v1/invoices/991', 'DELETE');
    assert.strictEqual(deleteCheck.blocked, true);

    const billingCheck = SafetyGovernor.isBlocked('/api/v1/billing/charge_card', 'POST');
    assert.strictEqual(billingCheck.blocked, true);
  });

  test('Upgrade 2: OpenApiParser ingests Swagger/OpenAPI specs into endpoints', () => {
    const mockOpenApi = {
      paths: {
        '/api/v1/users/{id}': {
          get: { summary: 'Get User' },
          put: { summary: 'Update User' }
        },
        '/api/v1/auth/login': {
          post: { summary: 'Login' }
        }
      }
    };

    const endpoints = OpenApiParser.parseSchema(mockOpenApi);
    assert.strictEqual(endpoints.length, 3);
    assert.ok(endpoints.some(ep => ep.path === '/api/v1/users/{id}' && ep.method === 'PUT'));
  });

  test('Upgrade 3: MassAssignmentStriker generates privilege escalation candidates', () => {
    const ep = {
      path: '/api/v1/users/{id}',
      method: 'PUT' as const,
      parameters: ['id'],
      isStateMutating: true
    };

    const candidates = MassAssignmentStriker.generateCandidates(ep, BASE_URL, ATTACKER_TOKEN, VICTIM_ID);
    assert.strictEqual(candidates.length, 1);
    assert.strictEqual(candidates[0].vector, 'MASS_ASSIGNMENT_VIOLATION');
    assert.ok(candidates[0].body?.includes('"role":"admin"'));
  });

  test('Module 2: JwtMutator creates valid alg: none bypass payload', () => {
    const sampleToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const noneToken = JwtMutator.createAlgNoneToken(sampleToken);
    assert.ok(noneToken !== null);
    
    const parts = noneToken.split('.');
    assert.strictEqual(parts.length, 3);
    assert.strictEqual(parts[2], '');
    
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    assert.strictEqual(header.alg, 'none');
  });

  test('Module 3: IdorStriker formats cross-tenant attack candidate correctly', () => {
    const ep = {
      path: '/api/v1/invoices/:id',
      method: 'GET' as const,
      parameters: ['id'],
      isStateMutating: false
    };

    const context: DualSessionContext = {
      victimToken: 'victim_token_123',
      victimResourceId: VICTIM_ID,
      victimSecretIdentifier: VICTIM_SECRET,
      attackerToken: ATTACKER_TOKEN,
    };

    const candidates = IdorStriker.generateCandidates(ep, BASE_URL, context);
    assert.strictEqual(candidates.length, 1);
    assert.strictEqual(candidates[0].targetUrl, `${BASE_URL}/api/v1/invoices/${VICTIM_ID}`);
    assert.strictEqual(candidates[0].headers['Authorization'], `Bearer ${ATTACKER_TOKEN}`);
    assert.strictEqual(candidates[0].expectedLeakFragment, VICTIM_SECRET);
  });

  test('Module 4: BlastChamber isolates safe vs vulnerable endpoints with zero false positives', async () => {
    const chamber = new BlastChamber();

    const vulnerableCandidate = {
      vector: 'IDOR_READ_VIOLATION' as const,
      targetUrl: `${BASE_URL}/api/v1/invoices/${VICTIM_ID}`,
      method: 'GET' as const,
      headers: { 'Authorization': `Bearer ${ATTACKER_TOKEN}` },
      expectedLeakFragment: VICTIM_SECRET,
    };

    const { result: vulnResult, receipt } = await chamber.executeCandidate(vulnerableCandidate);
    assert.strictEqual(vulnResult.passed, true);
    assert.strictEqual(vulnResult.verdict, 'CONFIRMED_VULNERABILITY');
    assert.ok(receipt !== null);
    assert.strictEqual(receipt.statusCode, 200);

    const secureCandidate = {
      vector: 'IDOR_READ_VIOLATION' as const,
      targetUrl: `${BASE_URL}/api/v1/users/${VICTIM_ID}/profile`,
      method: 'GET' as const,
      headers: { 'Authorization': `Bearer ${ATTACKER_TOKEN}` },
      expectedLeakFragment: 'SECRET_THAT_SHOULD_NEVER_LEAK',
    };

    const { result: secResult, receipt: secReceipt } = await chamber.executeCandidate(secureCandidate);
    assert.strictEqual(secResult.passed, false);
    assert.strictEqual(secResult.verdict, 'REFUTED_SAFE');
    assert.strictEqual(secReceipt, null);
  });

  test('Module 5: AshbornEngine end-to-end audit with Governor and Mass Assignment', async () => {
    const engine = new AshbornEngine();
    
    const scope: TargetScope = {
      name: 'Local Test Target',
      baseUrl: BASE_URL,
      allowedHosts: ['127.0.0.1'],
      rulesOfEngagement: 'Authorized testing only'
    };

    const mockOpenApi = {
      paths: {
        '/api/v1/invoices/{id}': {
          get: { summary: 'Vulnerable IDOR' }
        },
        '/api/v1/users/{id}': {
          put: { summary: 'Vulnerable Mass Assignment' }
        },
        '/api/v1/billing/users/{id}/charge': {
          post: { summary: 'Destructive Billing (Must be blocked)' }
        }
      }
    };

    const context: DualSessionContext = {
      victimToken: 'victim_token_123',
      victimResourceId: VICTIM_ID,
      victimSecretIdentifier: VICTIM_SECRET,
      attackerToken: ATTACKER_TOKEN,
    };

    const auditResult = await engine.auditTargetWithOpenApi(scope, mockOpenApi, context);

    assert.strictEqual(auditResult.endpointsScanned, 3);
    assert.strictEqual(auditResult.blockedByGovernor, 1); // /billing/charge was safely blocked!
    assert.strictEqual(auditResult.confirmedReceipts.length, 2); // 1 IDOR + 1 Mass Assignment!
    assert.strictEqual(auditResult.reports.length, 2);

    const massReport = auditResult.reports.find(r => r.vulnerabilityClass.includes('CWE-915'));
    assert.ok(massReport !== undefined);
    assert.ok(massReport.title.includes('Mass Assignment'));
  });
});
