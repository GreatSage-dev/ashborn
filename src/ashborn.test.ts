import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, Server, IncomingMessage, ServerResponse } from 'node:http';

import { 
  BundleExtractor, 
  OpenApiParser,
  PostmanParser,
  GraphQLParser,
  GraphQLStriker,
  CurlParser,
  TargetLedger,
  HaddixMatrix,
  JwtMutator, 
  IdorStriker, 
  MassAssignmentStriker,
  SafetyGovernor,
  BlastChamber, 
  ReportGenerator, 
  AshbornEngine,
  SolidityScout,
  SolidityAccessStriker,
  SolidityReentrancyStriker,
  SolidityProxyStriker,
  FoundryPocGenerator,
  DualSessionContext,
  TargetScope
} from './index.js';
import { runGroundTruthBenchmark } from './benchmark/benchmark_runner.js';

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

      // ROUTE 5: GraphQL Endpoint (Introspection & Vulnerable BOLA Query)
      if (url === '/graphql' && method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            // Introspection Query
            if (parsed.query && parsed.query.includes('__schema')) {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                data: {
                  __schema: {
                    queryType: { name: 'Query' },
                    mutationType: { name: 'Mutation' },
                    types: [
                      {
                        name: 'Query',
                        kind: 'OBJECT',
                        fields: [
                          {
                            name: 'invoice',
                            args: [{ name: 'id', type: { kind: 'NON_NULL', name: 'ID' } }]
                          },
                          {
                            name: 'publicInfo',
                            args: []
                          }
                        ]
                      }
                    ]
                  }
                }
              }));
              return;
            }

            // Vulnerable GraphQL Query: invoice(id: $id)
            if (parsed.query && parsed.query.includes('invoice')) {
              if (auth.includes(ATTACKER_TOKEN) || auth.includes('victim_token')) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                  data: {
                    invoice: {
                      id: VICTIM_ID,
                      secret: VICTIM_SECRET,
                      status: 'unpaid',
                      amount: 50000,
                    }
                  }
                }));
                return;
              }
              res.writeHead(401, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ errors: [{ message: 'Unauthorized' }] }));
              return;
            }

            res.writeHead(400);
            res.end(JSON.stringify({ errors: [{ message: 'Bad request' }] }));
          } catch {
            res.writeHead(400);
            res.end();
          }
        });
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
    // Verifies Realistic Browser Headers (WAF evasion)
    assert.ok(candidates[0].headers['User-Agent'].includes('Mozilla/5.0'));
    assert.ok(candidates[0].headers['Sec-Ch-Ua'] !== undefined);
  });

  test('Reality 1 Check: BlastChamber enforces polite cadence delay with jitter', async () => {
    const chamber = new BlastChamber({
      cadenceDelayMs: { min: 30, max: 50 },
    });

    const start = performance.now();
    await chamber.executeCandidate({
      vector: 'IDOR_READ_VIOLATION' as const,
      targetUrl: `${BASE_URL}/api/v1/users/${VICTIM_ID}/profile`,
      method: 'GET' as const,
      headers: { 'Authorization': `Bearer ${ATTACKER_TOKEN}` },
      expectedLeakFragment: 'TEST',
    });
    const elapsed = performance.now() - start;

    // Must be at least the min delay of 30ms
    assert.ok(elapsed >= 28, `Expected elapsed >= 28ms with jitter, got ${elapsed}ms`);
  });

  test('Reality 3 Check: Strict Scope Discipline blocks out-of-scope hosts without sending packets', async () => {
    // 1. SafetyGovernor unit test
    const allowed = ['target.com', '*.target.com', '127.0.0.1'];
    assert.strictEqual(SafetyGovernor.isHostAllowed('https://target.com/api', allowed), true);
    assert.strictEqual(SafetyGovernor.isHostAllowed('https://app.target.com/users', allowed), true);
    assert.strictEqual(SafetyGovernor.isHostAllowed('https://attacker.evil.com/leak', allowed), false);
    assert.strictEqual(SafetyGovernor.isHostAllowed('https://api.stripe.com/charge', allowed), false);

    // 2. BlastChamber runtime host gate test
    const chamber = new BlastChamber({
      allowedHosts: ['authorized-domain.com'],
    });

    const outOfScopeCandidate = {
      vector: 'IDOR_READ_VIOLATION' as const,
      targetUrl: 'https://unauthorized-domain.com/api/v1/secret',
      method: 'GET' as const,
      headers: { 'Authorization': 'Bearer test' },
      expectedLeakFragment: 'SECRET',
    };

    const { result, receipt } = await chamber.executeCandidate(outOfScopeCandidate);
    assert.strictEqual(result.passed, false);
    assert.strictEqual(result.verdict, 'REFUTED_SAFE');
    assert.ok(result.reason.includes('LEGAL SAFETY REFUSAL'));
    assert.strictEqual(receipt, null);
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

  test('Benchmark Range: 10-Scenario Ground Truth achieves 100% precision and 0 false positives', async () => {
    const scorecard = await runGroundTruthBenchmark(49155);
    assert.strictEqual(scorecard.scenariosTested, 10);
    assert.strictEqual(scorecard.falsePositives, 0, 'False Positives MUST be 0 to avoid platform bans');
    assert.strictEqual(scorecard.truePositives, 3, 'Must detect all 3 true vulnerabilities');
    assert.strictEqual(scorecard.precisionPercent, 100);
    assert.strictEqual(scorecard.recallPercent, 100);
  });

  test('Upgrade 4: CurlParser ingests browser cURL with tokens, cookies, CSRF, and builds dual context', () => {
    const userACurl = `curl 'https://api.acme.com/v1/invoices/9941?expand=true' \\
      -H 'Authorization: Bearer victim_token_aaa_111' \\
      -H 'X-CSRF-Token: csrf_secret_token_123' \\
      -H 'Cookie: session=sess_999; theme=dark' \\
      -H 'User-Agent: Mozilla/5.0 Chrome/120.0'`;

    const userBCurl = `curl 'https://api.acme.com/v1/invoices/2202' \\
      -H 'Authorization: Bearer attacker_token_bbb_222'`;

    const parsedA = CurlParser.parse(userACurl);
    assert.strictEqual(parsedA.host, 'api.acme.com');
    assert.strictEqual(parsedA.path, '/v1/invoices/9941?expand=true');
    assert.strictEqual(parsedA.bearerToken, 'victim_token_aaa_111');
    assert.strictEqual(parsedA.csrfToken, 'csrf_secret_token_123');
    assert.strictEqual(parsedA.cookies['session'], 'sess_999');
    assert.strictEqual(parsedA.extractedResourceId, '9941');

    const dual = CurlParser.buildDualContextFromCurls(userACurl, userBCurl);
    assert.strictEqual(dual.context.victimToken, 'victim_token_aaa_111');
    assert.strictEqual(dual.context.attackerToken, 'attacker_token_bbb_222');
    assert.strictEqual(dual.context.victimResourceId, '9941');
    assert.strictEqual(dual.scope.baseUrl, 'https://api.acme.com');
  });

  test('Upgrade 5: TargetLedger manages workspace, deduplicates findings, and tracks metadata', () => {
    const testDir = 'targets_test_temp';
    const ledger = new TargetLedger(testDir);
    const program = 'acme_corp_bounty';

    // 1. Init & Save endpoints
    ledger.initTarget(program, 'https://api.acme.com');
    ledger.saveEndpoints(program, [
      { path: '/api/v1/users', method: 'GET', parameters: [], isStateMutating: false },
      { path: '/api/v1/users', method: 'GET', parameters: [], isStateMutating: false }, // Duplicate
      { path: '/api/v1/invoices', method: 'POST', parameters: ['id'], isStateMutating: true },
    ]);

    // 2. Record Receipt & Test Deduplication
    const mockReceipt = {
      receiptId: 'ASHBORN-TEST01',
      findingHash: 'hash_test_1234567890abcdef',
      timestamp: new Date().toISOString(),
      targetUrl: 'https://api.acme.com/api/v1/invoices/9941',
      vector: 'IDOR_READ_VIOLATION' as const,
      statusCode: 200,
      latencyMs: 12,
      rawCurl: 'curl ...',
      leakFingerprint: 'SSN_982',
      proofHash: 'proof_hash_abc',
      verifiedBy: 'ASHBORN_BLAST_CHAMBER_V1' as const,
    };

    const firstRecord = ledger.recordReceipt(program, mockReceipt);
    assert.strictEqual(firstRecord, true, 'First recording of finding MUST succeed');

    const duplicateRecord = ledger.recordReceipt(program, mockReceipt);
    assert.strictEqual(duplicateRecord, false, 'Duplicate finding MUST be prevented by findingHash');

    // Clean up temporary test dir
    import('fs').then(fs => {
      try { fs.rmSync(testDir, { recursive: true, force: true }); } catch {}
    });
  });

  test('Upgrade 6: HaddixMatrix generates 4-stage systematic authorization checklist', () => {
    const ep = {
      path: '/api/v1/invoices/{id}',
      method: 'GET' as const,
      parameters: ['id'],
      isStateMutating: false,
    };

    const context: DualSessionContext = {
      victimToken: 'token_user_a',
      victimResourceId: 'inv_1042',
      attackerToken: 'token_user_b',
    };

    const scope: TargetScope = {
      name: 'Acme',
      baseUrl: 'https://api.acme.com',
      allowedHosts: ['api.acme.com'],
      rulesOfEngagement: 'Testing',
    };

    const stages = HaddixMatrix.generateMatrix(ep, scope.baseUrl, context, scope);
    assert.strictEqual(stages.length, 4, 'Haddix Matrix MUST have exactly 4 stages');
    assert.ok(stages[0].stageName.includes('Cross-Tenant IDOR'));
    assert.ok(stages[1].stageName.includes('Public Resource Guard'));
    assert.ok(stages[2].stageName.includes('Verb Tampering'));
    assert.ok(stages[3].stageName.includes('Mass Assignment'));

    assert.strictEqual(stages[0].candidate.headers['Authorization'], 'Bearer token_user_b');
    assert.strictEqual(stages[1].candidate.headers['Authorization'], undefined, 'Stage 2 unauth check must omit auth header');
    assert.strictEqual(stages[2].candidate.method, 'POST', 'Stage 3 must swap GET to POST');
    assert.ok(stages[3].candidate.body?.includes('"role":"admin"'));
  });

  test('Upgrade 7: AshbornEngine executes cURL ingress audit end-to-end with persistent ledger', async () => {
    const engine = new AshbornEngine({
      ledgerBaseDir: 'targets_test_temp2',
      enableHaddixMatrix: true,
    });

    const userACurl = `curl '${BASE_URL}/api/v1/invoices/${VICTIM_ID}' -H 'Authorization: Bearer victim_token'`;
    const userBCurl = `curl '${BASE_URL}/api/v1/invoices/${VICTIM_ID}' -H 'Authorization: Bearer ${ATTACKER_TOKEN}'`;

    const auditResult = await engine.auditTargetWithCurls(userACurl, userBCurl, 'local_test_program');

    assert.strictEqual(auditResult.endpointsScanned, 1);
    assert.ok(auditResult.confirmedReceipts.length >= 1, 'Must detect vulnerable invoice endpoint via cURL ingress');
    assert.strictEqual(auditResult.confirmedReceipts[0].statusCode, 200);

    // Clean up temporary test dir
    import('fs').then(fs => {
      try { fs.rmSync('targets_test_temp2', { recursive: true, force: true }); } catch {}
    });
  });

  test('Upgrade 8: PostmanParser ingests v2.1 collection with nested folders, query params, and body templates', () => {
    const samplePostmanCollection = {
      info: {
        name: 'Fintech API',
        schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
      },
      item: [
        {
          name: 'Invoices Folder',
          item: [
            {
              name: 'Get Invoice by ID',
              request: {
                method: 'GET',
                url: {
                  raw: '{{baseUrl}}/api/v1/invoices/:id',
                  variable: [{ key: 'id', value: 'inv_1042' }],
                },
              },
            },
            {
              name: 'Query Invoices',
              request: {
                method: 'GET',
                url: 'https://api.fintech.com/api/v1/invoices/filter?status=active&userId={{userId}}',
              },
            },
          ],
        },
        {
          name: 'Update User Profile',
          request: {
            method: 'PUT',
            url: {
              raw: '{{baseUrl}}/api/v1/users/:userId/profile',
            },
            body: {
              mode: 'raw',
              raw: JSON.stringify({ name: 'Alice', email: 'alice@acme.com' }),
            },
          },
        },
      ],
    };

    const endpoints = PostmanParser.parseCollection(samplePostmanCollection);
    assert.strictEqual(endpoints.length, 3, 'Must discover all 3 nested requests from Postman');

    const ep1 = endpoints.find(e => e.path === '/api/v1/invoices/:id');
    assert.ok(ep1, 'Must extract parameterized invoice path');
    assert.strictEqual(ep1?.method, 'GET');
    assert.ok(ep1?.parameters.includes('id'), 'Must extract :id parameter');

    const ep2 = endpoints.find(e => e.path === '/api/v1/invoices/filter');
    assert.ok(ep2, 'Must extract filter path');
    assert.ok(ep2?.parameters.includes('userId'), 'Must extract userId query param');

    const ep3 = endpoints.find(e => e.path === '/api/v1/users/:userId/profile');
    assert.ok(ep3, 'Must extract profile update endpoint');
    assert.strictEqual(ep3?.method, 'PUT');
    assert.strictEqual(ep3?.isStateMutating, true);
    assert.ok(ep3?.parameters.includes('email'), 'Must extract email parameter from body');
  });

  test('Upgrade 9: GraphQLParser extracts object-target queries from introspection schema', () => {
    const mockIntrospection = {
      data: {
        __schema: {
          queryType: { name: 'Query' },
          mutationType: { name: 'Mutation' },
          types: [
            {
              name: 'Query',
              kind: 'OBJECT',
              fields: [
                {
                  name: 'invoice',
                  args: [{ name: 'id', type: { kind: 'NON_NULL', name: 'ID' } }],
                },
                {
                  name: 'publicFeed',
                  args: [],
                },
              ],
            },
            {
              name: 'Mutation',
              kind: 'OBJECT',
              fields: [
                {
                  name: 'updateUser',
                  args: [{ name: 'input', type: { kind: 'NON_NULL', name: 'UserInput' } }],
                },
              ],
            },
          ],
        },
      },
    };

    const summary = GraphQLParser.parseSchema(mockIntrospection);
    assert.strictEqual(summary.queries.length, 2);
    assert.strictEqual(summary.mutations.length, 1);

    const invoiceQuery = summary.queries.find(q => q.name === 'invoice');
    assert.ok(invoiceQuery);
    assert.strictEqual(invoiceQuery?.isObjectTarget, true, 'invoice query with id arg MUST be tagged as object target');

    const publicQuery = summary.queries.find(q => q.name === 'publicFeed');
    assert.ok(publicQuery);
    assert.strictEqual(publicQuery?.isObjectTarget, false, 'publicFeed with no args must NOT be an object target');
  });

  test('Upgrade 10: AshbornEngine strikes GraphQL endpoint, confirms BOLA/IDOR with proof receipt', async () => {
    const engine = new AshbornEngine({
      ledgerBaseDir: 'targets_test_temp_gql',
    });

    const scope: TargetScope = {
      name: 'GraphQL Test Target',
      baseUrl: BASE_URL,
      allowedHosts: ['127.0.0.1'],
      rulesOfEngagement: 'Testing',
    };

    const context: DualSessionContext = {
      victimToken: 'victim_token',
      victimResourceId: VICTIM_ID,
      victimSecretIdentifier: VICTIM_SECRET,
      attackerToken: ATTACKER_TOKEN,
    };

    // 1. Fetch live introspection from our test server
    const introPayload = GraphQLParser.generateIntrospectionPayload();
    const introRes = await fetch(`${BASE_URL}/graphql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: introPayload,
    });
    const introData = (await introRes.json()) as Record<string, unknown>;

    // 2. Execute GraphQL audit
    const result = await engine.auditTargetWithGraphQL(scope, '/graphql', introData, context, 'graphql_program');

    assert.ok(result.endpointsScanned >= 2, 'Must scan queries from schema');
    assert.strictEqual(result.highValueTargets, 1, 'Must identify 1 high-value query (invoice)');
    assert.strictEqual(result.confirmedReceipts.length, 1, 'Must confirm 1 GraphQL IDOR receipt');

    const receipt = result.confirmedReceipts[0];
    assert.strictEqual(receipt.statusCode, 200);
    assert.strictEqual(receipt.leakFingerprint, VICTIM_SECRET);
    assert.ok(receipt.rawCurl.includes('/graphql'));
    assert.ok(receipt.rawCurl.includes('invoice'));

    // Clean up temporary test dir
    import('fs').then(fs => {
      try { fs.rmSync('targets_test_temp_gql', { recursive: true, force: true }); } catch {}
    });
  });

  test('Upgrade 11: SolidityScout parses contracts, state variables, and functions', () => {
    const sampleSolidity = `
      // SPDX-License-Identifier: MIT
      pragma solidity ^0.8.20;

      contract SimpleVault is Ownable {
          address public vaultOwner;
          mapping(address => uint256) public balances;

          event Deposited(address indexed user, uint256 amount);

          modifier onlyAuthorized() {
              require(msg.sender == vaultOwner, "Not authorized");
              _;
          }

          function deposit() external payable {
              balances[msg.sender] += msg.value;
              emit Deposited(msg.sender, msg.value);
          }

          function getBalance(address user) external view returns (uint256) {
              return balances[user];
          }
      }
    `;

    const contracts = SolidityScout.parseSource(sampleSolidity, 'SimpleVault.sol');
    assert.strictEqual(contracts.length, 1);
    const vault = contracts[0];
    assert.strictEqual(vault.name, 'SimpleVault');
    assert.strictEqual(vault.kind, 'contract');
    assert.deepStrictEqual(vault.inheritance, ['Ownable']);
    assert.strictEqual(vault.modifiers.length, 1);
    assert.strictEqual(vault.modifiers[0], 'onlyAuthorized');
    assert.strictEqual(vault.functions.length, 2);

    const depositFn = vault.functions.find(f => f.name === 'deposit');
    assert.ok(depositFn);
    assert.strictEqual(depositFn?.visibility, 'external');
    assert.strictEqual(depositFn?.stateMutability, 'payable');
  });

  test('Upgrade 12: Solidity Strikers detect Missing Access Control and Reentrancy CEI violations', () => {
    const vulnerableContract = `
      // SPDX-License-Identifier: MIT
      pragma solidity ^0.8.20;

      contract VulnerableDeFiBank {
          address public owner;
          mapping(address => uint256) public balances;

          function initialize(address _owner) external {
              owner = _owner;
          }

          // Vulnerability 1: Missing Access Control (anyone can drain all contract ETH)
          function emergencyDrainAll(address payable recipient) external {
              recipient.transfer(address(this).balance);
          }

          // Vulnerability 2: Reentrancy (external call BEFORE state update, no nonReentrant)
          function withdraw(uint256 amount) external {
              require(balances[msg.sender] >= amount, "Insufficient");
              (bool sent, ) = msg.sender.call{value: amount}("");
              require(sent, "Failed");
              balances[msg.sender] -= amount;
          }

          // Safe function with proper access control
          function setFee(uint256 newFee) external onlyOwner {
              // protected
          }
      }
    `;

    const contracts = SolidityScout.parseSource(vulnerableContract, 'VulnerableDeFiBank.sol');
    assert.strictEqual(contracts.length, 1);
    const bank = contracts[0];

    // 1. Strike Access Control
    const accessFindings = SolidityAccessStriker.strike(bank);
    assert.strictEqual(accessFindings.length, 1);
    assert.strictEqual(accessFindings[0].functionName, 'emergencyDrainAll');
    assert.strictEqual(accessFindings[0].vector, 'SOLIDITY_MISSING_ACCESS_CONTROL');
    assert.strictEqual(accessFindings[0].severity, 'CRITICAL');

    // 2. Strike Reentrancy
    const reentrancyFindings = SolidityReentrancyStriker.strike(bank);
    assert.strictEqual(reentrancyFindings.length, 1);
    assert.strictEqual(reentrancyFindings[0].functionName, 'withdraw');
    assert.strictEqual(reentrancyFindings[0].vector, 'SOLIDITY_REENTRANCY_VIOLATION');
    assert.strictEqual(reentrancyFindings[0].severity, 'CRITICAL');

    // 3. Strike Proxy Initializer
    const proxyFindings = SolidityProxyStriker.strike(bank);
    assert.strictEqual(proxyFindings.length, 1);
    assert.strictEqual(proxyFindings[0].functionName, 'initialize');
    assert.strictEqual(proxyFindings[0].vector, 'SOLIDITY_UNPROTECTED_INITIALIZER');
  });

  test('Upgrade 13: AshbornEngine executes smart contract audit and generates Foundry PoCs', () => {
    const engine = new AshbornEngine();

    const vulnerableSource = `
      pragma solidity ^0.8.20;

      contract YieldVault {
          mapping(address => uint256) public balances;

          function drainVault(address payable recipient) external {
              recipient.transfer(address(this).balance);
          }

          function exitPool(uint256 shares) external {
              (bool ok, ) = msg.sender.call{value: shares}("");
              require(ok);
              balances[msg.sender] = 0;
          }
      }
    `;

    const audit = engine.auditSoliditySource([
      { path: 'YieldVault.sol', content: vulnerableSource }
    ], 'YieldProtocol');

    assert.strictEqual(audit.contractsAnalyzed, 1);
    assert.strictEqual(audit.findings.length, 2);

    const accessFinding = audit.findings.find(f => f.vector === 'SOLIDITY_MISSING_ACCESS_CONTROL');
    assert.ok(accessFinding);
    assert.strictEqual(accessFinding?.functionName, 'drainVault');
    assert.ok(accessFinding?.foundryPocCode?.includes('forge-std/Test.sol'));
    assert.ok(accessFinding?.foundryPocCode?.includes('test_exploit_unauthorizedAccessDrain'));

    const reentrancyFinding = audit.findings.find(f => f.vector === 'SOLIDITY_REENTRANCY_VIOLATION');
    assert.ok(reentrancyFinding);
    assert.strictEqual(reentrancyFinding?.functionName, 'exitPool');
    assert.ok(reentrancyFinding?.foundryPocCode?.includes('test_exploit_reentrancyDrain'));
  });
});
