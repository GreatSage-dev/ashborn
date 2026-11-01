/**
 * SAFETY GOVERNOR MODULE
 * Enforces strict compliance with Bug Bounty Rules of Engagement and prevents
 * accidental destructive or financial side effects on target systems.
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
   * Determines whether an endpoint path or method is prohibited by safety rules.
   */
  public static isBlocked(
    path: string, 
    method: string, 
    customPatterns: RegExp[] = []
  ): { blocked: boolean; reason?: string } {
    const methodUpper = method.toUpperCase();

    // Absolute ban on automated DELETE methods on production infrastructure
    if (methodUpper === 'DELETE') {
      return {
        blocked: true,
        reason: 'DELETE method prohibited by safety policy to prevent data loss.',
      };
    }

    const allPatterns = [...this.DEFAULT_BLOCKED_PATTERNS, ...customPatterns];
    for (const pattern of allPatterns) {
      if (pattern.test(path)) {
        return {
          blocked: true,
          reason: `Path matches safety blocklist pattern: ${pattern.toString()}`,
        };
      }
    }

    return { blocked: false };
  }
}
