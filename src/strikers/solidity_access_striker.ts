import { SolidityContract, SolidityFinding } from '../types.js';

/**
 * SOLIDITY ACCESS CONTROL STRIKER
 * Hunts for functions performing sensitive state changes or fund transfers
 * without authorization modifiers or caller identity verification.
 */
export class SolidityAccessStriker {
  private static readonly AUTH_MODIFIERS = new Set([
    'onlyowner',
    'onlyrole',
    'onlyadmin',
    'auth',
    'adminonly',
    'requiresauth',
    'onlygovernor',
    'onlytimelock',
    'onlyminter',
    'onlymanager',
    'onlyauthorized'
  ]);

  private static readonly SENSITIVE_OPERATIONS = [
    { pattern: /\bselfdestruct\s*\(/, desc: 'Contract destruction (selfdestruct)' },
    { pattern: /\bowner\s*=\s*/, desc: 'Ownership reassignment' },
    { pattern: /\badmin\s*=\s*/, desc: 'Admin role reassignment' },
    { pattern: /\bfee\s*=\s*/, desc: 'Fee parameter tampering' },
    { pattern: /\b_mint\s*\(/, desc: 'Arbitrary token minting' },
    { pattern: /\bupgradeTo\s*\(/, desc: 'Contract logic upgrade' },
    { pattern: /\b(?:recipient|to|target|destination)\s*\.\s*(?:transfer|transferFrom|safeTransfer)\s*\(/, desc: 'Arbitrary recipient transfer' },
    { pattern: /\b(?:recipient|to|target|destination)\s*\.\s*call\s*\{[^}]*value\s*:/, desc: 'Arbitrary raw ETH transfer via low-level call' },
    { pattern: /\.transfer\s*\(\s*address\s*\(\s*this\s*\)\s*\.\s*balance\s*\)/, desc: 'Drain entire contract balance' },
  ];

  public static strike(contract: SolidityContract): SolidityFinding[] {
    const findings: SolidityFinding[] = [];

    // Skip interfaces and libraries as they don't hold state or user funds directly
    if (contract.kind === 'interface' || contract.kind === 'library') {
      return findings;
    }

    for (const func of contract.functions) {
      // Internal and private functions can only be called from inside
      if (func.visibility !== 'public' && func.visibility !== 'external') {
        continue;
      }

      // Constructors are only run during deployment
      if (func.name === 'constructor') {
        continue;
      }

      // Initialization functions are audited separately by SolidityProxyStriker
      if (/^initialize(?:[0-9a-zA-Z_]*)?$/i.test(func.name) || func.name === 'init') {
        continue;
      }

      // View and pure functions cannot modify state or drain funds
      if (func.stateMutability === 'view' || func.stateMutability === 'pure') {
        continue;
      }

      // Check if function has an explicit auth modifier
      const hasAuthModifier = func.modifiers.some((m) =>
        this.AUTH_MODIFIERS.has(m.toLowerCase())
      );

      // Check if function body contains inline sender verification
      const hasInlineAuthCheck = 
        /require\s*\(\s*msg\.sender\s*==/.test(func.body) ||
        /require\s*\(\s*hasRole\s*\(/.test(func.body) ||
        /if\s*\(\s*msg\.sender\s*!=/.test(func.body) ||
        /if\s*\(\s*!hasRole\s*\(/.test(func.body);

      if (hasAuthModifier || hasInlineAuthCheck) {
        continue;
      }

      // Inspect function body for sensitive operations
      for (const op of this.SENSITIVE_OPERATIONS) {
        if (op.pattern.test(func.body)) {
          findings.push({
            contractName: contract.name,
            functionName: func.name,
            filePath: contract.filePath,
            line: func.startLine,
            vector: 'SOLIDITY_MISSING_ACCESS_CONTROL',
            severity: 'CRITICAL',
            description: `Function '${func.name}' performs '${op.desc}' with ${func.visibility} visibility but lacks an access control modifier (e.g. onlyOwner) or caller verification.`,
            impact: `Any unauthenticated caller or malicious actor can call '${func.name}()' to manipulate critical state or drain protocol funds directly.`,
            remediation: `Apply an authorization modifier such as 'onlyOwner' or verify caller permissions using 'require(msg.sender == owner, "UNAUTHORIZED");'.`,
          });
          break; // Avoid duplicate findings on the same function
        }
      }
    }

    return findings;
  }
}
