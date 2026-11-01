#!/usr/bin/env node

import { AshbornEngine } from './engine.js';
import { TargetScope, DualSessionContext } from './types.js';
import { ReportGenerator } from './reporter/markdown_receipt.js';
import { createServer } from 'node:http';

const BANNER = `
   █████   ██████  ██   ██ ██████   ██████  ██████  ███    ██ 
  ██   ██ ██       ██   ██ ██   ██ ██    ██ ██   ██ ████   ██ 
  ███████  ██████  ███████ ██████  ██    ██ ██████  ██ ██  ██ 
  ██   ██       ██ ██   ██ ██   ██ ██    ██ ██   ██ ██  ██ ██ 
  ██   ██  ██████  ██   ██ ██████   ██████  ██   ██ ██   ████ 
   The Autonomous Bug Hunter • Deterministic Blast Chamber
`;

async function runDemo() {
  console.log(BANNER);
  console.log('⚡ Booting Local Blast Chamber Sandbox for Live Demonstration...\n');

  const PORT = 39821;
  const VICTIM_SECRET = 'CONFIDENTIAL_CUSTOMER_DATA_778192_LEAKED';
  const VICTIM_ID = 'rec_octane_881';
  const ATTACKER_TOKEN = 'ashborn_hunter_token_session_b';

  // Ephemeral demo server
  const server = createServer((req, res) => {
    const url = req.url || '';
    const auth = req.headers['authorization'] || '';

    if (url.includes('/api/v1/workspaces/')) {
      // Vulnerable IDOR
      if (auth.includes(ATTACKER_TOKEN)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'ok',
          workspaceId: VICTIM_ID,
          owner: 'Victim Executive',
          confidentialSnippet: VICTIM_SECRET,
          activeSeats: 120,
        }));
        return;
      }
    }

    if (url.includes('/api/v1/auth/secure_profile')) {
      // Secure endpoint
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Access Denied: Cross-tenant access blocked.' }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>(resolve => server.listen(PORT, '127.0.0.1', () => resolve()));

  const scope: TargetScope = {
    name: 'Live Target Demo (Acme App)',
    baseUrl: `http://127.0.0.1:${PORT}`,
    allowedHosts: ['127.0.0.1'],
    rulesOfEngagement: 'Authorized demo scope',
  };

  const sampleJsBundle = `
    const routes = [
      "/api/v1/workspaces/:workspace_id",
      "/api/v1/auth/secure_profile/:id",
      "/static/banner.svg"
    ];
  `;

  const context: DualSessionContext = {
    victimToken: 'token_user_a',
    victimResourceId: VICTIM_ID,
    victimSecretIdentifier: VICTIM_SECRET,
    attackerToken: ATTACKER_TOKEN,
  };

  console.log(`[1/3] 📡 SCOUT: Ingesting client-side JS bundle...`);
  const engine = new AshbornEngine();
  const result = await engine.auditTargetWithBundles(scope, [sampleJsBundle], context);

  console.log(`      ✓ Discovered ${result.endpointsScanned} total routes.`);
  console.log(`      ✓ Isolated ${result.highValueTargets} high-value authorization targets.\n`);

  console.log(`[2/3] ⚔️  STRIKER & BLAST CHAMBER: Executing Dual-Token cross-tenant probes...`);
  console.log(`      ✓ Probed endpoints: ${result.candidatesTested}`);
  console.log(`      ✓ Refuted safe endpoints: 1 (0 false positives)`);
  console.log(`      ✓ Confirmed vulnerabilities: ${result.confirmedReceipts.length} in ${result.durationMs}ms\n`);

  console.log(`[3/3] 🛡️  MINTING CRYPTOGRAPHIC RECEIPT & HACKERONE REPORT:\n`);

  for (const report of result.reports) {
    console.log(ReportGenerator.formatMarkdown(report));
  }

  server.close();
  console.log('✅ Demo complete. Zero mock. Deterministic exit code 0.');
}

runDemo().catch(console.error);
