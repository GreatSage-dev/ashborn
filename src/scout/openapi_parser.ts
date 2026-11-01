import { DiscoveredEndpoint, HttpMethod } from '../types.js';

export interface OpenApiSchema {
  paths?: Record<string, Record<string, {
    parameters?: Array<{ name: string; in: string; required?: boolean }>;
    summary?: string;
    description?: string;
  }>>;
}

/**
 * OPENAPI / SWAGGER INGESTOR (Schema Ingress Alpha)
 * Parses OpenAPI and Swagger JSON specifications into structured endpoints.
 */
export class OpenApiParser {
  private static readonly VALID_METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

  public static parseSchema(schemaJson: string | OpenApiSchema): DiscoveredEndpoint[] {
    const schema: OpenApiSchema = typeof schemaJson === 'string' ? JSON.parse(schemaJson) : schemaJson;
    const endpoints: DiscoveredEndpoint[] = [];

    if (!schema.paths) {
      return endpoints;
    }

    for (const [path, methods] of Object.entries(schema.paths)) {
      for (const [methodKey, operation] of Object.entries(methods)) {
        const methodUpper = methodKey.toUpperCase() as HttpMethod;
        if (!this.VALID_METHODS.includes(methodUpper)) {
          continue;
        }

        const parameters: string[] = [];
        if (Array.isArray(operation.parameters)) {
          for (const param of operation.parameters) {
            if (param.name && !parameters.includes(param.name)) {
              parameters.push(param.name);
            }
          }
        }

        // Also extract {id} parameters embedded directly in the path template
        const pathMatches = path.matchAll(/\{([a-zA-Z0-9_]+)\}/g);
        for (const m of pathMatches) {
          if (!parameters.includes(m[1])) {
            parameters.push(m[1]);
          }
        }

        const isStateMutating = methodUpper !== 'GET';

        endpoints.push({
          path,
          method: methodUpper,
          parameters,
          isStateMutating,
          sourceBundle: 'openapi-specification',
        });
      }
    }

    return endpoints;
  }
}
