import { DiscoveredEndpoint, HttpMethod } from '../types.js';

/**
 * SCOUT MODULE (Lostsec Alpha)
 * Scans client-side JavaScript bundles to extract hidden API routes in <10ms.
 */
export class BundleExtractor {
  // Regex patterns to capture internal API routes from compiled frontend bundles
  private static readonly API_ROUTE_REGEX = /(?:['"`])(\/(?:api|v[0-9]|graphql|internal|auth|user|admin)\/[a-zA-Z0-9_\-\/:\$\{\}]+)(?:['"`])/g;
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

      // Infer mutation nature
      const isStateMutating = /(update|create|delete|remove|patch|edit|set|upload|cancel|transfer)/i.test(rawPath);
      const inferredMethod: HttpMethod = isStateMutating ? 'POST' : 'GET';

      // Deduplicate by path
      if (!endpointsMap.has(rawPath)) {
        endpointsMap.set(rawPath, {
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
