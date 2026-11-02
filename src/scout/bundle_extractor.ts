import { DiscoveredEndpoint, HttpMethod } from '../types.js';

/**
 * SCOUT MODULE (Lostsec Alpha)
 * Scans client-side JavaScript bundles to extract hidden API routes in <10ms.
 */
export class BundleExtractor {
  // Regex patterns to capture internal API routes and absolute URLs from compiled frontend bundles
  private static readonly API_ROUTE_REGEX = /(?:['"`])((?:https?:\/\/[a-zA-Z0-9_\-\.]+|\/(?:api|v[0-9]|graphql|internal|auth|user|admin))\/[a-zA-Z0-9_\-\/:\$\{\}\.]+)(?:['"`])/g;
  private static readonly PARAMETER_REGEX = /[:\$]([a-zA-Z0-9_]+)|\{([a-zA-Z0-9_]+)\}|[\?&]([a-zA-Z0-9_]+)=/g;

  /**
   * Parses raw JavaScript bundle content and extracts structured endpoints.
   */
  public static extractEndpoints(bundleContent: string, sourceName: string = 'bundle.js'): DiscoveredEndpoint[] {
    const endpointsMap = new Map<string, DiscoveredEndpoint>();
    const matches = bundleContent.matchAll(this.API_ROUTE_REGEX);

    for (const match of matches) {
      const rawPath = match[1];

      // Filter out static asset noise (e.g. /api/avatar.png)
      if (rawPath.match(/\.(png|jpg|jpeg|svg|css|woff2?|ico)$/i)) {
        continue;
      }

      // Extract parameter names
      const parameters: string[] = [];
      const paramMatches = rawPath.matchAll(this.PARAMETER_REGEX);
      for (const p of paramMatches) {
        const paramName = p[1] || p[2] || p[3];
        if (paramName && !parameters.includes(paramName)) {
          parameters.push(paramName);
        }
      }

      // Infer HTTP method from statement context (bounded by statement separators)
      const matchIndex = match.index ?? 0;
      const prevSep = Math.max(
        bundleContent.lastIndexOf(';', matchIndex),
        bundleContent.lastIndexOf('\n', matchIndex)
      );
      const nextSep = Math.min(
        bundleContent.indexOf(';', matchIndex) !== -1 ? bundleContent.indexOf(';', matchIndex) : bundleContent.length,
        bundleContent.indexOf('\n', matchIndex) !== -1 ? bundleContent.indexOf('\n', matchIndex) : bundleContent.length
      );

      const statementWindow = bundleContent.slice(
        prevSep === -1 ? Math.max(0, matchIndex - 40) : prevSep,
        nextSep === bundleContent.length ? Math.min(bundleContent.length, matchIndex + rawPath.length + 60) : nextSep
      );

      let inferredMethod: HttpMethod = 'GET';
      if (/method\s*:\s*['"]PUT['"]|\.put\s*\(/i.test(statementWindow)) {
        inferredMethod = 'PUT';
      } else if (/method\s*:\s*['"]PATCH['"]|\.patch\s*\(/i.test(statementWindow)) {
        inferredMethod = 'PATCH';
      } else if (/method\s*:\s*['"]DELETE['"]|\.delete\s*\(/i.test(statementWindow)) {
        inferredMethod = 'DELETE';
      } else if (/method\s*:\s*['"]POST['"]|\.post\s*\(/i.test(statementWindow) || /(update|create|delete|remove|patch|edit|set|upload|cancel|transfer)/i.test(rawPath)) {
        inferredMethod = 'POST';
      }

      const isStateMutating = inferredMethod !== 'GET';

      // Deduplicate by method + path
      const key = `${inferredMethod}:${rawPath}`;
      if (!endpointsMap.has(key)) {
        endpointsMap.set(key, {
          path: rawPath,
          method: inferredMethod,
          parameters,
          isStateMutating,
          sourceBundle: sourceName,
        });
      }
    }

    return Array.from(endpointsMap.values());
  }

  /**
   * Filters discovered endpoints to high-value authorization targets (endpoints with IDs).
   */
  public static filterHighValueTargets(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
    return endpoints.filter(ep => 
      ep.parameters.some(p => /(id|user|account|org|team|invoice|order|doc|profile)/i.test(p)) ||
      /(user|account|org|order|invoice|profile|admin)\/[0-9a-fA-F\-\:\$]+/i.test(ep.path)
    );
  }
}
