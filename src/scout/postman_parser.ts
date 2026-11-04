import { DiscoveredEndpoint, HttpMethod } from '../types.js';

export interface PostmanUrlObject {
  raw?: string;
  host?: string[] | string;
  path?: string[] | string;
  query?: Array<{ key: string; value?: string; disabled?: boolean }>;
  variable?: Array<{ key: string; value?: string; disabled?: boolean }>;
}

export interface PostmanRequest {
  method?: string;
  url?: string | PostmanUrlObject;
  header?: Array<{ key: string; value: string; disabled?: boolean }>;
  body?: {
    mode?: string;
    raw?: string;
  };
}

export interface PostmanItem {
  name?: string;
  request?: PostmanRequest;
  item?: PostmanItem[];
}

export interface PostmanCollection {
  info?: {
    name?: string;
    schema?: string;
    description?: string;
  };
  item?: PostmanItem[];
}

/**
 * POSTMAN COLLECTION INGESTOR (v2.0 & v2.1)
 * Extracts API routes, methods, and parameters from Postman collection JSON exports.
 */
export class PostmanParser {
  private static readonly VALID_METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

  public static parseCollection(collectionJson: string | PostmanCollection): DiscoveredEndpoint[] {
    const collection: PostmanCollection = typeof collectionJson === 'string'
      ? JSON.parse(collectionJson)
      : collectionJson;

    const endpoints: DiscoveredEndpoint[] = [];
    if (!collection || !Array.isArray(collection.item)) {
      return endpoints;
    }

    this.traverseItems(collection.item, endpoints);
    return this.deduplicateEndpoints(endpoints);
  }

  private static traverseItems(items: PostmanItem[], endpoints: DiscoveredEndpoint[]): void {
    for (const item of items) {
      if (item.request) {
        const parsed = this.parseRequest(item.request);
        if (parsed) {
          endpoints.push(parsed);
        }
      }

      // Recursively traverse folders/nested items
      if (Array.isArray(item.item) && item.item.length > 0) {
        this.traverseItems(item.item, endpoints);
      }
    }
  }

  private static parseRequest(req: PostmanRequest): DiscoveredEndpoint | null {
    const rawMethod = (req.method || 'GET').toUpperCase();
    if (!this.VALID_METHODS.includes(rawMethod as HttpMethod)) {
      return null;
    }
    const method = rawMethod as HttpMethod;

    let rawPath = '';
    const parameters: string[] = [];

    if (typeof req.url === 'string') {
      rawPath = this.extractPathFromUrlString(req.url);
    } else if (req.url && typeof req.url === 'object') {
      if (req.url.raw) {
        rawPath = this.extractPathFromUrlString(req.url.raw);
      } else if (Array.isArray(req.url.path)) {
        rawPath = '/' + req.url.path.join('/');
      } else if (typeof req.url.path === 'string') {
        rawPath = req.url.path.startsWith('/') ? req.url.path : `/${req.url.path}`;
      }

      // Collect URL variables
      if (Array.isArray(req.url.variable)) {
        for (const v of req.url.variable) {
          if (v.key && !parameters.includes(v.key)) {
            parameters.push(v.key);
          }
        }
      }

      // Collect Query parameters
      if (Array.isArray(req.url.query)) {
        for (const q of req.url.query) {
          if (q.key && !parameters.includes(q.key)) {
            parameters.push(q.key);
          }
        }
      }
    }

    if (!rawPath) {
      return null;
    }

    // Normalize path (ensure leading slash, strip trailing slash)
    let normalizedPath = rawPath.split('?')[0];
    if (!normalizedPath.startsWith('/')) {
      normalizedPath = `/${normalizedPath}`;
    }
    if (normalizedPath.length > 1 && normalizedPath.endsWith('/')) {
      normalizedPath = normalizedPath.slice(0, -1);
    }

    // Extract query parameters from URL string if present
    if (rawPath.includes('?')) {
      const queryString = rawPath.split('?')[1] || '';
      const queryPairs = queryString.split('&');
      for (const pair of queryPairs) {
        const key = pair.split('=')[0];
        if (key && !parameters.includes(key)) {
          parameters.push(key);
        }
        const valMatches = pair.matchAll(/\{\{([a-zA-Z0-9_]+)\}\}/g);
        for (const vm of valMatches) {
          if (vm[1] && !parameters.includes(vm[1])) {
            parameters.push(vm[1]);
          }
        }
      }
    }

    // Extract path parameters: :param, {{param}}, {param}
    const pathMatches = normalizedPath.matchAll(/[:{]([a-zA-Z0-9_]+)[}]*/g);
    for (const m of pathMatches) {
      const paramName = m[1].replace(/[{}]/g, '');
      if (paramName && !parameters.includes(paramName)) {
        parameters.push(paramName);
      }
    }

    // Extract parameters from JSON body if present
    if (req.body?.mode === 'raw' && req.body.raw) {
      try {
        const bodyObj = JSON.parse(req.body.raw);
        if (typeof bodyObj === 'object' && bodyObj !== null && !Array.isArray(bodyObj)) {
          for (const key of Object.keys(bodyObj)) {
            if (!parameters.includes(key)) {
              parameters.push(key);
            }
          }
        }
      } catch {}
    }

    return {
      path: normalizedPath,
      method,
      parameters,
      isStateMutating: method !== 'GET',
      sourceBundle: 'postman-collection',
    };
  }

  private static extractPathFromUrlString(urlStr: string): string {
    // Strip {{baseUrl}} or http(s)://host(:port)
    let cleaned = urlStr.replace(/^https?:\/\/[^/]+/i, '');
    cleaned = cleaned.replace(/^\{\{[a-zA-Z0-9_-]+\}\}/i, '');
    if (!cleaned.startsWith('/')) {
      cleaned = '/' + cleaned;
    }
    return cleaned;
  }

  private static deduplicateEndpoints(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
    const seen = new Set<string>();
    const unique: DiscoveredEndpoint[] = [];
    for (const ep of endpoints) {
      const key = `${ep.method}:${ep.path}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(ep);
      }
    }
    return unique;
  }
}
