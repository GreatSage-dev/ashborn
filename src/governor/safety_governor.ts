export interface SafetyCheckResult {
  blocked: boolean;
  reason?: string;
  scopeViolation?: boolean;
}

/**
 * SAFETY GOVERNOR MODULE
 * Enforces strict compliance with Bug Bounty Rules of Engagement and prevents
 * accidental destructive, financial, or out-of-scope actions on target systems.
 */
export class SafetyGovernor {
  private static readonly DEFAULT_BLOCKED_PATTERNS: RegExp[] = [
    /\/delete/i,
    /\/destroy/i,
    /\/remove/i,
    /\/purge/i,
    /\/billing/i,
    /\/payment/i,
    /\/charge/i,
    /\/pay\b/i,
    /\/invoice\/pay/i,
    /\/subscribe/i,
    /\/unsubscribe/i,
    /\/broadcast/i,
    /\/mass[-_]?mail/i,
    /\/reset[-_]?password/i,
    /\/transfer[-_]?funds/i,
  ];

  /**
   * Deterministically validates whether a target URL's hostname is in the authorized scope.
   * Supports exact match ("api.target.com") and wildcard subdomains ("*.target.com").
   */
  public static isHostAllowed(urlOrPath: string, allowedHosts: string[]): boolean {
    if (!allowedHosts || allowedHosts.length === 0) {
      return true; // No host restrictions configured
    }

    // If it's a relative path, it inherits the caller's target scope
    if (urlOrPath.startsWith('/')) {
      return true;
    }

    try {
      const parsed = new URL(urlOrPath);
      const targetHost = parsed.hostname.toLowerCase();

      return allowedHosts.some(allowed => {
        const clean = allowed.toLowerCase().trim();
        if (clean === targetHost) return true;
        if (clean.startsWith('*.') && targetHost.endsWith(clean.slice(1))) return true;
        return false;
      });
    } catch {
      // Malformed URL is strictly blocked
      return false;
    }
  }

  /**
   * Determines whether an endpoint path, method, or host is prohibited by safety rules.
   */
  public static isBlocked(
    pathOrUrl: string, 
    method: string, 
    customPatterns: RegExp[] = [],
    allowedHosts: string[] = []
  ): SafetyCheckResult {
    const methodUpper = method.toUpperCase();

    // 1. STRICT SCOPE DISCIPLINE: Refuse packet if host is out-of-scope
    if (!this.isHostAllowed(pathOrUrl, allowedHosts)) {
      return {
        blocked: true,
        scopeViolation: true,
        reason: `LEGAL SAFETY REFUSAL: Target host is OUT OF SCOPE. No packets transmitted.`,
      };
    }

    // 2. Absolute ban on automated DELETE methods on production infrastructure
    if (methodUpper === 'DELETE') {
      return {
        blocked: true,
        reason: 'DELETE method prohibited by safety policy to prevent data loss.',
      };
    }

    // 3. Destructive / Billing pattern blocklist
    const allPatterns = [...this.DEFAULT_BLOCKED_PATTERNS, ...customPatterns];
    for (const pattern of allPatterns) {
      if (pattern.test(pathOrUrl)) {
        return {
          blocked: true,
          reason: `Path matches safety blocklist pattern: ${pattern.toString()}`,
        };
      }
    }

    return { blocked: false };
  }
}

