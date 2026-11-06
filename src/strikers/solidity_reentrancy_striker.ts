import { SolidityContract, SolidityFinding } from '../types.js';

/**
 * SOLIDITY REENTRANCY STRIKER
 * Detects violations of the Checks-Effects-Interactions (CEI) pattern
 * where external ether/token calls precede state variable updates without a reentrancy guard.
 */
export class SolidityReentrancyStriker {
  private static readonly REENTRANCY_GUARDS = new Set([
    'nonreentrant',
    'reentrancyguard',
    'lock',
    'nonreentrantview',
    'mutex'
  ]);

  public static strike(contract: SolidityContract): SolidityFinding[] {
    const findings: SolidityFinding[] = [];

    if (contract.kind === 'interface' || contract.kind === 'library') {
      return findings;
    }

    for (const func of contract.functions) {
      if (func.visibility !== 'public' && func.visibility !== 'external') {
        continue;
      }

      if (func.stateMutability === 'view' || func.stateMutability === 'pure') {
        continue;
      }

      // Check if guarded by reentrancy modifier
      const hasReentrancyGuard = func.modifiers.some((m) =>
        this.REENTRANCY_GUARDS.has(m.toLowerCase())
      );
      if (hasReentrancyGuard) {
        continue;
      }

      // Find external call patterns
      const externalCallRegex = /(?:(\.call\s*\{[^}]*value\s*:)|(\.transfer\s*\()|(\.send\s*\()|(?:IERC20|IERC721|IERC1155|[a-zA-Z0-9_]+Token)\s*\([^)]*\)\s*\.\s*(?:transfer|transferFrom)\s*\()/g;

      let callMatch: RegExpExecArray | null;
      while ((callMatch = externalCallRegex.exec(func.body)) !== null) {
        const callIndex = callMatch.index;
        const codeAfterCall = func.body.substring(callIndex + callMatch[0].length);

        // Check if state is modified AFTER this call (CEI violation)
        // Patterns: `balances[...] =`, `total -=`, `isProcessed = true`, `delete ...`
        const stateModificationAfterCall = /(?:[a-zA-Z0-9_]+(?:\s*\[[^\]]+\])*\s*(?:=|\+=|-=|\*=|\/=|%=|\+\+|--))|(?:\bdelete\s+[a-zA-Z0-9_]+)/.test(codeAfterCall);

        // Make sure it's not just a local variable declaration like `bool success =`
        const isLocalVarOnly = /^\s*bool\s+[a-zA-Z0-9_]+\s*=/.test(codeAfterCall.trim()) && !codeAfterCall.includes(';');

        if (stateModificationAfterCall && !isLocalVarOnly) {
          findings.push({
            contractName: contract.name,
            functionName: func.name,
            filePath: contract.filePath,
            line: func.startLine,
            vector: 'SOLIDITY_REENTRANCY_VIOLATION',
            severity: 'CRITICAL',
            description: `Function '${func.name}' violates Checks-Effects-Interactions (CEI): external value/token transfer occurs before state variables are updated, and no 'nonReentrant' modifier is present.`,
            impact: `A malicious recipient contract can invoke fallback/receive to re-enter '${func.name}()' recursively before state updates occur, draining all contract balances in a single transaction.`,
            remediation: `Adhere strictly to Checks-Effects-Interactions: update state balances BEFORE making external calls, or apply OpenZeppelin's 'nonReentrant' modifier.`,
          });
          break; // Avoid multi-flagging same function
        }
      }
    }

    return findings;
  }
}
