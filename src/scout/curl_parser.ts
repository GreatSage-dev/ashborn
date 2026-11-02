import { HttpMethod, DualSessionContext, TargetScope } from '../types.js';

export interface ParsedCurl {
  rawUrl: string;
  baseUrl: string;
  path: string;
  host: string;
  method: HttpMethod;
  headers: Record<string, string>;
  body?: string;
  bearerToken?: string;
  csrfToken?: string;
  cookies: Record<string, string>;
  extractedResourceId?: string;
}

/**
 * CURL & HAR INGRESS PARSER
 * Inspired by Lostsec (Coffinxp) & Jason Haddix DEF CON methodology.
 * Translates raw browser 'Copy as cURL' commands into structured attack contexts.
 */
export class CurlParser {
  /**
   * Parses a raw cURL command (Bash or CMD syntax).
   */
  public static parse(curlCommand: string): ParsedCurl {
    const cleaned = curlCommand
      .replace(/\\\r?\n/g, ' ') // join multiline bash continuations
      .replace(/\^\r?\n/g, ' ') // join multiline cmd continuations
      .trim();

    // 1. Extract URL
    // Matches curl 'http...' or curl "http..." or curl http...
    const urlMatch = cleaned.match(/curl\s+(?:-[A-Za-z0-9_-]+\s+(?:'[^']*'|"[^"]*"|\S+)\s+)*(?:'([^']+)'|"([^"]+)"|(\bhttps?:\/\/[^\s'"]+))/i)
      || cleaned.match(/(?:'([^']*(?:https?:\/\/)[^']*)'|"([^"]*(?:https?:\/\/)[^"]*)"|(\bhttps?:\/\/[^\s'"]+))/i);

    let rawUrl = '';
    if (urlMatch) {
      rawUrl = urlMatch[1] || urlMatch[2] || urlMatch[3] || '';
    }

    if (!rawUrl) {
      throw new Error('Invalid cURL command: Could not extract target URL.');
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawUrl);
    } catch {
      throw new Error(`Invalid URL extracted from cURL: ${rawUrl}`);
    }

    const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;
    const path = parsedUrl.pathname + parsedUrl.search;
    const host = parsedUrl.hostname;

    // 2. Extract Method
    let method: HttpMethod = 'GET';
    const methodMatch = cleaned.match(/(?:-X|--request)\s+['"]?([A-Z]+)['"]?/i);
    if (methodMatch) {
      const explicitMethod = methodMatch[1].toUpperCase() as HttpMethod;
      if (['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(explicitMethod)) {
        method = explicitMethod;
      }
    } else if (cleaned.includes('--data') || cleaned.includes('-d ') || cleaned.includes('--data-raw')) {
      method = 'POST';
    }

    // 3. Extract Headers
    const headers: Record<string, string> = {};
    const headerRegex = /(?:-H|--header)\s+(?:'([^']+)'|"([^"]+)")/g;
    let hMatch: RegExpExecArray | null;
    while ((hMatch = headerRegex.exec(cleaned)) !== null) {
      const headerStr = hMatch[1] || hMatch[2];
      const colonIndex = headerStr.indexOf(':');
      if (colonIndex > 0) {
        const key = headerStr.slice(0, colonIndex).trim();
        const value = headerStr.slice(colonIndex + 1).trim();
        headers[key] = value;
        headers[key.toLowerCase()] = value; // case-insensitive accessibility
      }
    }

    // 4. Extract Body
    let body: string | undefined;
    const bodyMatch = cleaned.match(/(?:--data|--data-raw|--data-binary|-d)\s+(?:'([^']*)'|"([^"]*)")/);
    if (bodyMatch) {
      body = bodyMatch[1] ?? bodyMatch[2];
    }

    // 5. Extract Bearer Token & Authentication
    let bearerToken: string | undefined;
    const authHeader = headers['authorization'] || headers['Authorization'];
    if (authHeader) {
      const tokenMatch = authHeader.match(/Bearer\s+([A-Za-z0-9\-._~+/]+=*)/i);
      if (tokenMatch) {
        bearerToken = tokenMatch[1];
      } else {
        bearerToken = authHeader.trim();
      }
    }

    // 6. Extract CSRF Tokens
    const csrfKeys = ['x-csrf-token', 'x-xsrf-token', 'csrf-token', 'xsrf-token', 'x-csrftoken'];
    let csrfToken: string | undefined;
    for (const key of csrfKeys) {
      if (headers[key]) {
        csrfToken = headers[key];
        break;
      }
    }

    // 7. Extract Cookies
    const cookies: Record<string, string> = {};
    const cookieHeader = headers['cookie'] || headers['Cookie'];
    if (cookieHeader) {
      const pairs = cookieHeader.split(';');
      for (const pair of pairs) {
        const [k, ...v] = pair.trim().split('=');
        if (k) {
          cookies[k] = v.join('=');
        }
      }
      // If no bearer token found, check for jwt or session cookie
      if (!bearerToken) {
        bearerToken = cookies['session'] || cookies['jwt'] || cookies['token'] || cookies['auth_token'];
      }
    }

    // 8. Extract Potential Resource ID from URL path or body
    let extractedResourceId: string | undefined;
    const uuidMatch = path.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/);
    if (uuidMatch) {
      extractedResourceId = uuidMatch[0];
    } else {
      const idSegmentMatch = path.match(/\/(?:invoices|users|accounts|orgs|teams|orders|customers|profiles)\/([a-zA-Z0-9_\-]+)(?:\/|\.|\?|$)/i);
      if (idSegmentMatch) {
        extractedResourceId = idSegmentMatch[1];
      } else {
        const idMatch = path.match(/\/(\d{2,10})(?:\/|\.|\?|$)/);
        if (idMatch) {
          extractedResourceId = idMatch[1];
        }
      }
    }

    return {
      rawUrl,
      baseUrl,
      path,
      host,
      method,
      headers,
      body,
      bearerToken,
      csrfToken,
      cookies,
      extractedResourceId,
    };
  }

  /**
   * Helper: Builds a DualSessionContext directly from User A cURL and User B cURL.
   */
  public static buildDualContextFromCurls(
    userACurl: string,
    userBCurl: string,
    fallbackResourceId = '1001'
  ): { context: DualSessionContext; scope: TargetScope; primaryCurl: ParsedCurl } {
    const parsedA = this.parse(userACurl);
    const parsedB = this.parse(userBCurl);

    const victimToken = parsedA.bearerToken || 'user_a_token';
    const attackerToken = parsedB.bearerToken || 'user_b_token';
    const victimResourceId = parsedA.extractedResourceId || fallbackResourceId;

    const scope: TargetScope = {
      name: parsedA.host,
      baseUrl: parsedA.baseUrl,
      allowedHosts: [parsedA.host],
      rulesOfEngagement: 'Authorized dual-token audit ingested via cURL.',
    };

    const context: DualSessionContext = {
      victimToken,
      attackerToken,
      victimResourceId,
    };

    return { context, scope, primaryCurl: parsedA };
  }
}
