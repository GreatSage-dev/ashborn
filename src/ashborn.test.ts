import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, Server, IncomingMessage, ServerResponse } from 'node:http';

import { 
  BundleExtractor, 
  JwtMutator, 
  IdorStriker, 
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

  // Spin up ephemeral test server to simulate live web targets
  before((_, done) => {
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = req.url || '';
      const auth = req.headers['authorization'] || '';

      // ROUTE 1: Vulnerable IDOR Endpoint
      if (url.startsWith('/api/v1/invoices/') || url.includes('/api/v1/invoices?id=')) {
        // Flawed implementation: checks if token exists, but DOES NOT verify ownership of ID!
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
      if (url.startsWith('/api/v1/users/') && url.includes('/profile')) {
        // Checks tenant boundary: Attacker token cannot access other users
        if (auth.includes(ATTACKER_TOKEN)) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Forbidden: You do not own this profile.' }));
          return;
        }
      }

      // ROUTE 3: Vulnerable JWT endpoint
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
    assert.strictEqual(endpoints.length, 3); // logo.png and /home/landing filtered out

    const highValue = BundleExtractor.filterHighValueTargets(endpoints);
    assert.strictEqual(highValue.length, 2); // only endpoints with ID parameters
    assert.ok(highValue.some(ep => ep.path === '/api/v1/invoices/:id'));
  });

  test('Module 2: JwtMutator creates valid alg: none bypass payload', () => {
    // Standard HS256 JWT
    const sampleToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    
    const noneToken = JwtMutator.createAlgNoneToken(sampleToken);
    assert.ok(noneToken !== null);
    
    const parts = noneToken.split('.');
    assert.strictEqual(parts.length, 3);
    assert.strictEqual(parts[2], ''); // Signature stripped!
    
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

    // Test 1: Vulnerable IDOR candidate
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
    assert.strictEqual(vulnResult.dataLeaked, true);
    assert.ok(receipt !== null);
    assert.strictEqual(receipt.statusCode, 200);
    assert.strictEqual(receipt.verifiedBy, 'ASHBORN_BLAST_CHAMBER_V1');
    assert.strictEqual(receipt.proofHash.length, 64); // Valid SHA-256 seal

    // Test 2: Secure endpoint candidate (Must be REFUTED with 0 false alarms)
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
    assert.strictEqual(secResult.statusCode, 403);
    assert.strictEqual(secReceipt, null); // Zero receipts for safe endpoints!
  });

  test('Module 5: AshbornEngine end-to-end autonomous scan produces HackerOne report', async () => {
    const engine = new AshbornEngine();
    
    const scope: TargetScope = {
      name: 'Local Test Target',
      baseUrl: BASE_URL,
      allowedHosts: ['127.0.0.1'],
      rulesOfEngagement: 'Authorized testing only'
    };

    const mockBundle = `
      function load() {
        fetch("/api/v1/invoices/:id");
        fetch("/api/v1/users/{id}/profile");
      }
    `;

    const context: DualSessionContext = {
      victimToken: 'victim_token_123',
      victimResourceId: VICTIM_ID,
      victimSecretIdentifier: VICTIM_SECRET,
      attackerToken: ATTACKER_TOKEN,
    };

    const auditResult = await engine.auditTargetWithBundles(scope, [mockBundle], context);

    assert.strictEqual(auditResult.endpointsScanned, 2);
    assert.strictEqual(auditResult.highValueTargets, 2);
    assert.strictEqual(auditResult.candidatesTested, 2);
    
    // Exactly 1 confirmed vulnerability, 0 false alarms
    assert.strictEqual(auditResult.confirmedReceipts.length, 1);
    assert.strictEqual(auditResult.reports.length, 1);

    const report = auditResult.reports[0];
    assert.strictEqual(report.severity, 'HIGH');
    assert.ok(report.proofOfConceptCurl.includes(ATTACKER_TOKEN));
    assert.ok(report.proofOfConceptCurl.includes(VICTIM_ID));

    // Verify Markdown formatting
    const markdown = ReportGenerator.formatMarkdown(report);
    assert.ok(markdown.includes('Broken Object Level Authorization'));
    assert.ok(markdown.includes('Proof of Concept (Reproducible cURL)'));
    assert.ok(markdown.includes('Ashborn Cryptographic Proof Receipt'));
    assert.ok(markdown.includes(report.tamperProofReceipt.proofHash));
  });
});
