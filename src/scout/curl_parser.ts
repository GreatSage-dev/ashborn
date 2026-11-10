import { HttpMethod, DualSessionContext, TargetScope } from '../types.js';

export interface ParsedCurl {
  rawUrl: string;
  baseUrl: string;
  path: string;
  host: string;
  method: HttpMethod;
  headers: Record<string, string>;
  replayHeaders: Record<string, string>;
  body?: string;
  bearerToken?: string;
  csrfToken?: string;
  cookies: Record<string, string>;
  extractedResourceId?: string;
}

const IGNORED_REPLAY_HEADERS = new Set([
  'host',
  'content-length',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'accept-encoding',
  'te',
  'trailer',
  'upgrade',
]);

/**
 * CURL & HAR INGRESS PARSER
 * Inspired by Lostsec (Coffinxp) & Jason Haddix DEF CON methodology.
 * Translates raw browser 'Copy as cURL' commands (Bash, ANSI-C $'...', and Windows CMD) into structured attack contexts.
 */
export class CurlParser {
  /**
   * Tokenizes a raw cURL command across POSIX Bash, $'...' ANSI-C strings, and Windows CMD (^ escapes).
   */
  public static tokenize(curlCommand: string): string[] {
    const isCmdEscaped =
      /\^\r?\n/.test(curlCommand) ||
      /\^\\?\^"/.test(curlCommand) ||
      /\^[&|<>%]/.test(curlCommand);

    const joined = curlCommand
      .replace(/\\\r?\n/g, ' ') // join multiline bash continuations
      .replace(/\^\r?\n/g, ' ') // join multiline Windows CMD continuations
      .trim();

    const tokens: string[] = [];
    let i = 0;
    const len = joined.length;

    while (i < len) {
      while (i < len && /\s/.test(joined[i])) {
        i++;
      }
      if (i >= len) break;

      let current = '';
      let hasToken = false;

      while (i < len && !/\s/.test(joined[i])) {
        // 1. Bash ANSI-C quoting: $'...'
        if (joined[i] === '$' && joined[i + 1] === "'") {
          hasToken = true;
          i += 2;
          while (i < len && joined[i] !== "'") {
            if (joined[i] === '\\' && i + 1 < len) {
              const next = joined[i + 1];
              if (next === "'" || next === '\\' || next === '"') {
                current += next;
                i += 2;
              } else if (next === 'n') {
                current += '\n';
                i += 2;
              } else if (next === 'r') {
                current += '\r';
                i += 2;
              } else if (next === 't') {
                current += '\t';
                i += 2;
              } else if (next === 'x' && /^[0-9a-fA-F]{2}/.test(joined.slice(i + 2, i + 4))) {
                current += String.fromCharCode(parseInt(joined.slice(i + 2, i + 4), 16));
                i += 4;
              } else if (next === 'u' && /^[0-9a-fA-F]{4}/.test(joined.slice(i + 2, i + 6))) {
                current += String.fromCharCode(parseInt(joined.slice(i + 2, i + 6), 16));
                i += 6;
              } else {
                current += next;
                i += 2;
              }
            } else {
              current += joined[i++];
            }
          }
          if (i < len && joined[i] === "'") i++;
          continue;
        }

        // 2. Single-quoted string: '...'
        if (joined[i] === "'") {
          hasToken = true;
          i++;
          while (i < len && joined[i] !== "'") {
            current += joined[i++];
          }
          if (i < len && joined[i] === "'") i++;
          continue;
        }

        // 3. Double-quoted string: "..." (supports both Bash \" and Windows CMD ^\^" / ^" / ^&)
        if (joined[i] === '"') {
          hasToken = true;
          i++;
          while (i < len) {
            if (joined.startsWith('^\\^"', i)) {
              current += '"';
              i += 4;
            } else if (joined.startsWith('^"', i)) {
              current += '"';
              i += 2;
            } else if (joined.startsWith('\\"', i)) {
              current += '"';
              i += 2;
            } else if (joined.startsWith('\\\\', i)) {
              current += '\\';
              i += 2;
            } else if (isCmdEscaped && joined[i] === '^' && i + 1 < len) {
              current += joined[i + 1];
              i += 2;
            } else if (joined[i] === '"') {
              i++;
              break;
            } else {
              current += joined[i++];
            }
          }
          continue;
        }

        // 4. Unquoted character sequence
        hasToken = true;
        if (isCmdEscaped && joined[i] === '^' && i + 1 < len) {
          current += joined[i + 1];
          i += 2;
        } else if (!isCmdEscaped && joined[i] === '\\' && i + 1 < len) {
          current += joined[i + 1];
          i += 2;
        } else {
          current += joined[i++];
        }
      }

      if (hasToken) {
        tokens.push(current);
      }
    }

    return tokens;
  }

  /**
   * Parses a raw cURL command (Bash or Windows CMD syntax).
   */
  public static parse(curlCommand: string): ParsedCurl {
    const tokens = this.tokenize(curlCommand);
    if (tokens.length === 0) {
      throw new Error('Invalid cURL command: Could not extract target URL.');
    }

    let startIdx = 0;
    if (/^curl(?:\.exe)?$/i.test(tokens[0])) {
      startIdx = 1;
    }

    let rawUrl = '';
    let explicitMethod: string | undefined;
    const headers: Record<string, string> = {};
    const originalHeaders: Record<string, string> = {};
    const cookieStrings: string[] = [];
    const bodyParts: string[] = [];

    const recordHeader = (rawHeader: string) => {
      const trimmed = rawHeader.trim();
      // Skip HTTP/2 pseudo-headers like :authority, :method, :path, :scheme
      if (trimmed.startsWith(':')) return;
      const colonIndex = trimmed.indexOf(':');
      if (colonIndex > 0) {
        const key = trimmed.slice(0, colonIndex).trim();
        const value = trimmed.slice(colonIndex + 1).trim();
        headers[key] = value;
        headers[key.toLowerCase()] = value;
        // Deduplicate case-insensitively in originalHeaders
        for (const existingKey of Object.keys(originalHeaders)) {
          if (existingKey.toLowerCase() === key.toLowerCase()) {
            delete originalHeaders[existingKey];
          }
        }
        originalHeaders[key] = value;
      }
    };

    for (let idx = startIdx; idx < tokens.length; idx++) {
      const tok = tokens[idx];

      // --url <url> or --url=<url>
      if (tok === '--url' && idx + 1 < tokens.length) {
        rawUrl = tokens[++idx];
        continue;
      }
      if (tok.startsWith('--url=')) {
        rawUrl = tok.slice('--url='.length);
        continue;
      }

      // -X / --request
      if ((tok === '-X' || tok === '--request') && idx + 1 < tokens.length) {
        explicitMethod = tokens[++idx].toUpperCase();
        continue;
      }
      if (tok.startsWith('-X') && tok.length > 2) {
        explicitMethod = tok.slice(2).toUpperCase();
        continue;
      }
      if (tok.startsWith('--request=')) {
        explicitMethod = tok.slice('--request='.length).toUpperCase();
        continue;
      }

      // -H / --header
      if ((tok === '-H' || tok === '--header') && idx + 1 < tokens.length) {
        recordHeader(tokens[++idx]);
        continue;
      }
      if (tok.startsWith('-H') && tok.length > 2) {
        recordHeader(tok.slice(2));
        continue;
      }
      if (tok.startsWith('--header=')) {
        recordHeader(tok.slice('--header='.length));
        continue;
      }

      // -b / --cookie (Chrome DevTools default cookie flag)
      if ((tok === '-b' || tok === '--cookie') && idx + 1 < tokens.length) {
        cookieStrings.push(tokens[++idx]);
        continue;
      }
      if (tok.startsWith('-b') && tok.length > 2 && tok.includes('=')) {
        cookieStrings.push(tok.slice(2));
        continue;
      }
      if (tok.startsWith('--cookie=')) {
        cookieStrings.push(tok.slice('--cookie='.length));
        continue;
      }

      // -d / --data / --data-raw / --data-binary / --data-ascii / --data-urlencode
      if (
        (tok === '-d' ||
          tok === '--data' ||
          tok === '--data-raw' ||
          tok === '--data-binary' ||
          tok === '--data-ascii' ||
          tok === '--data-urlencode') &&
        idx + 1 < tokens.length
      ) {
        bodyParts.push(tokens[++idx]);
        continue;
      }
      if (tok.startsWith('--data-raw=')) {
        bodyParts.push(tok.slice('--data-raw='.length));
        continue;
      }
      if (tok.startsWith('--data-binary=')) {
        bodyParts.push(tok.slice('--data-binary='.length));
        continue;
      }
      if (tok.startsWith('--data=')) {
        bodyParts.push(tok.slice('--data='.length));
        continue;
      }

      // -A / --user-agent
      if ((tok === '-A' || tok === '--user-agent') && idx + 1 < tokens.length) {
        recordHeader(`User-Agent: ${tokens[++idx]}`);
        continue;
      }

      // -e / --referer
      if ((tok === '-e' || tok === '--referer') && idx + 1 < tokens.length) {
        recordHeader(`Referer: ${tokens[++idx]}`);
        continue;
      }

      // -u / --user (Basic Auth)
      if ((tok === '-u' || tok === '--user') && idx + 1 < tokens.length) {
        const encoded = Buffer.from(tokens[++idx], 'utf-8').toString('base64');
        recordHeader(`Authorization: Basic ${encoded}`);
        continue;
      }

      // Positional HTTP(S) URL
      if (!rawUrl && /^https?:\/\//i.test(tok)) {
        rawUrl = tok;
      }
    }

    // Fallback regex URL scan if URL was embedded unusually
    if (!rawUrl) {
      const fallbackMatch = curlCommand.match(/https?:\/\/[^\s'"\\^]+/i);
      if (fallbackMatch) {
        rawUrl = fallbackMatch[0];
      }
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

    // Determine HTTP Method
    const body = bodyParts.length > 0 ? bodyParts.join('&') : undefined;
    let method: HttpMethod = 'GET';
    if (explicitMethod && ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(explicitMethod)) {
      method = explicitMethod as HttpMethod;
    } else if (body !== undefined) {
      method = 'POST';
    }

    // Merge Cookies from both -H 'Cookie: ...' and -b / --cookie
    const cookies: Record<string, string> = {};
    const headerCookie = headers['cookie'] || headers['Cookie'];
    if (headerCookie) {
      cookieStrings.unshift(headerCookie);
    }

    for (const rawCookieStr of cookieStrings) {
      const pairs = rawCookieStr.split(';');
      for (const pair of pairs) {
        const trimmedPair = pair.trim();
        if (!trimmedPair) continue;
        const eqIdx = trimmedPair.indexOf('=');
        if (eqIdx > 0) {
          const k = trimmedPair.slice(0, eqIdx).trim();
          const v = trimmedPair.slice(eqIdx + 1).trim();
          cookies[k] = v;
        }
      }
    }

    // Sync normalized Cookie header back into headers & originalHeaders when cookies exist
    const cookieEntries = Object.entries(cookies);
    if (cookieEntries.length > 0) {
      const serializedCookies = cookieEntries.map(([k, v]) => `${k}=${v}`).join('; ');
      headers['Cookie'] = serializedCookies;
      headers['cookie'] = serializedCookies;
      for (const existingKey of Object.keys(originalHeaders)) {
        if (existingKey.toLowerCase() === 'cookie') {
          delete originalHeaders[existingKey];
        }
      }
      originalHeaders['Cookie'] = serializedCookies;
    }

    // Extract Bearer Token / Session Identifier
    let bearerToken: string | undefined;
    const authHeader = headers['authorization'] || headers['Authorization'];
    if (authHeader) {
      const tokenMatch = authHeader.match(/^Bearer\s+(.+)$/i);
      if (tokenMatch) {
        bearerToken = tokenMatch[1].trim();
      } else {
        bearerToken = authHeader.trim();
      }
    }

    // Extract CSRF / XSRF Tokens (explicit header first, then URL-decoded cookie fallback)
    const csrfKeys = ['x-csrf-token', 'x-xsrf-token', 'csrf-token', 'xsrf-token', 'x-csrftoken', 'anti-csrf-token'];
    let csrfToken: string | undefined;
    for (const key of csrfKeys) {
      if (headers[key]) {
        csrfToken = headers[key];
        break;
      }
    }
    if (!csrfToken) {
      const csrfCookieVal = cookies['XSRF-TOKEN'] || cookies['xsrf-token'] || cookies['csrftoken'] || cookies['_csrf'];
      if (csrfCookieVal) {
        try {
          csrfToken = decodeURIComponent(csrfCookieVal);
        } catch {
          csrfToken = csrfCookieVal;
        }
      }
    }

    // Fallback session token from cookies if no Authorization header was sent
    if (!bearerToken && cookieEntries.length > 0) {
      bearerToken =
        cookies['session'] ||
        cookies['jwt'] ||
        cookies['token'] ||
        cookies['auth_token'] ||
        cookies['access_token'] ||
        cookies['sid'] ||
        cookies['connect.sid'] ||
        cookies['PHPSESSID'] ||
        cookies['JSESSIONID'];

      if (!bearerToken) {
        const dynamicSessionEntry = cookieEntries.find(
          ([k]) => /(session|sess|jwt|auth|token|sid)/i.test(k) && !/(xsrf|csrf)/i.test(k)
        );
        if (dynamicSessionEntry) {
          bearerToken = dynamicSessionEntry[1];
        }
      }
    }

    // Build safe replayHeaders (strips hop-by-hop headers like host / content-length / accept-encoding)
    const replayHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(originalHeaders)) {
      if (!IGNORED_REPLAY_HEADERS.has(key.toLowerCase())) {
        replayHeaders[key] = value;
      }
    }

    // Extract Potential Resource ID from URL path, query string, or JSON body
    const extractedResourceId = this.extractResourceId(parsedUrl, body);

    return {
      rawUrl,
      baseUrl,
      path,
      host,
      method,
      headers,
      replayHeaders,
      body,
      bearerToken,
      csrfToken,
      cookies,
      extractedResourceId,
    };
  }

  public static extractResourceId(parsedUrl: URL, body?: string): string | undefined {
    const pathname = parsedUrl.pathname;

    // 1. UUID anywhere in path
    const uuidMatch = pathname.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/);
    if (uuidMatch) return uuidMatch[0];

    // 2. Named collection segment followed by ID
    const idSegmentMatch = pathname.match(
      /\/(?:invoices|users|accounts|orgs|teams|orders|customers|profiles|workspaces|sessions|address-book|addresses|wallets|transactions|withdrawals|deposits|keys|api-keys|webhooks|tickets|messages|documents|files|projects|items|trades|transfers)\/([a-zA-Z0-9_\-]+)(?:\/|\.|\?|$)/i
    );
    if (idSegmentMatch) return idSegmentMatch[1];

    // 3. Pure numeric segment (e.g. /9941 or /42)
    const numericMatch = pathname.match(/\/(\d{1,24})(?:\/|\.|\?|$)/);
    if (numericMatch) return numericMatch[1];

    // 4. Prefixed identifier segment (e.g. rec_octane_881, inv_alpha_9918, addr_victim_77)
    const segments = pathname.split('/').filter(Boolean);
    for (let i = segments.length - 1; i >= 0; i--) {
      const seg = segments[i];
      if (/^v\d+$/i.test(seg) || /^oauth\d*$/i.test(seg)) continue;
      if (/^[a-zA-Z]{2,10}_[a-zA-Z0-9_\-]{2,}$/.test(seg) || /^[0-9a-f]{24}$/i.test(seg)) {
        return seg;
      }
    }

    // 5. Query parameters (?id=..., ?order_id=..., ?userId=...)
    for (const [k, v] of parsedUrl.searchParams.entries()) {
      if (/^(id|uuid|.*_id|.*Id)$/i.test(k) && v) {
        return v;
      }
    }

    // 6. JSON body ID fallback
    if (body && body.trim().startsWith('{')) {
      try {
        const parsedBody = JSON.parse(body) as Record<string, unknown>;
        for (const [k, v] of Object.entries(parsedBody)) {
          if (/^(id|uuid|.*_id|.*Id)$/i.test(k) && (typeof v === 'string' || typeof v === 'number')) {
            return String(v);
          }
        }
      } catch {}
    }

    return undefined;
  }

  private static computeCredentialFingerprint(parsed: ParsedCurl): string {
    const parts: string[] = [];
    const auth = parsed.headers['authorization'];
    if (auth) {
      parts.push(`auth:${auth.trim()}`);
    }
    const sortedCookies = Object.entries(parsed.cookies)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`);
    if (sortedCookies.length > 0) {
      parts.push(`cookies:${sortedCookies.join(';')}`);
    }
    if (parsed.csrfToken && parts.length === 0) {
      parts.push(`csrf:${parsed.csrfToken}`);
    }
    return parts.join('|');
  }

  /**
   * Helper: Builds a DualSessionContext directly from User A cURL and User B cURL.
   */
  public static buildDualContextFromCurls(
    userACurl: string,
    userBCurl: string,
    fallbackResourceId = '1001'
  ): { context: DualSessionContext; scope: TargetScope; primaryCurl: ParsedCurl; attackerCurl: ParsedCurl } {
    const parsedA = this.parse(userACurl);
    const parsedB = this.parse(userBCurl);

    // Guard against accidentally pasting two cURLs from the exact same logged-in session
    const credA = this.computeCredentialFingerprint(parsedA);
    const credB = this.computeCredentialFingerprint(parsedB);
    if (credA.length > 0 && credA === credB) {
      throw new Error(
        'Identical session credentials detected in User A and User B cURLs. Log into Account B in an Incognito or separate browser profile so both sessions are distinct.'
      );
    }

    const victimToken = parsedA.bearerToken || 'user_a_token';
    const attackerToken = parsedB.bearerToken || 'user_b_token';
    const victimResourceId = parsedA.extractedResourceId || fallbackResourceId;

    const scope: TargetScope = {
      name: parsedA.host,
      baseUrl: parsedA.baseUrl,
      allowedHosts: [parsedA.host],
      rulesOfEngagement: 'Authorized dual-session audit ingested via cURL.',
    };

    const context: DualSessionContext = {
      victimToken,
      attackerToken,
      victimResourceId,
      victimHeaders: parsedA.replayHeaders,
      attackerHeaders: parsedB.replayHeaders,
    };

    return { context, scope, primaryCurl: parsedA, attackerCurl: parsedB };
  }
}
