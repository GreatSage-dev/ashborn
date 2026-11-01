import { DiscoveredEndpoint, DualSessionContext, ExploitCandidate } from '../types.js';

/**
 * DUAL-TOKEN IDOR STRIKER (XBOW Core Engine)
 * Takes a victim's resource ID and constructs cross-tenant requests authenticated as the attacker.
 */
export class IdorStriker {
  /**
   * Generates cross-tenant exploit candidates for an endpoint.
   */
  public static generateCandidates(
    endpoint: DiscoveredEndpoint,
    baseUrl: string,
    context: DualSessionContext
  ): ExploitCandidate[] {
    const candidates: ExploitCandidate[] = [];

    // Replace parameter placeholder with victim's resource ID
    let resolvedPath = endpoint.path;
    const idPatterns = [
      /:[a-zA-Z0-9_]+/g,
      /\{[a-zA-Z0-9_]+\}/g,
      /\$[a-zA-Z0-9_]+/g,
    ];

    let replaced = false;
    for (const pattern of idPatterns) {
      if (pattern.test(resolvedPath)) {
        resolvedPath = resolvedPath.replace(pattern, context.victimResourceId);
        replaced = true;
      }
    }

    // If path didn't have a template placeholder, check if it ends with / or append query
    if (!replaced) {
      if (resolvedPath.endsWith('/')) {
        resolvedPath += context.victimResourceId;
      } else {
        const queryChar = resolvedPath.includes('?') ? '&' : '?';
        resolvedPath += `${queryChar}id=${encodeURIComponent(context.victimResourceId)}`;
      }
    }

    const fullUrl = `${baseUrl.replace(/\/$/, '')}/${resolvedPath.replace(/^\//, '')}`;

    // Read attack candidate
    candidates.push({
      vector: endpoint.isStateMutating ? 'IDOR_MUTATE_VIOLATION' : 'IDOR_READ_VIOLATION',
      targetUrl: fullUrl,
      method: endpoint.method,
      headers: {
        'Authorization': `Bearer ${context.attackerToken}`,
        'Content-Type': 'application/json',
        'User-Agent': 'Ashborn-Security-Auditor/1.0 (Authorized Bug Bounty Verification)',
      },
      body: endpoint.isStateMutating ? JSON.stringify({ resourceId: context.victimResourceId }) : undefined,
      expectedLeakFragment: context.victimSecretIdentifier,
    });

    return candidates;
  }
}
