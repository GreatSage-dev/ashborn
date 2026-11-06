import { SolidityContract, SolidityFinding } from '../types.js';

/**
 * SOLIDITY PROXY STRIKER
 * Hunts for uninitialized or unprotected initialize functions in upgradeable contracts.
 */
export class SolidityProxyStriker {
  private static readonly INIT_MODIFIERS = new Set([
    'initializer',
    'onlyinitializing',
    'reinitializer'
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

      // Check if function is an initialization entrypoint
      const isInitFunc = /^initialize(?:[0-9a-zA-Z_]*)?$/i.test(func.name) || func.name === 'init';
      if (!isInitFunc) {
        continue;
      }

      // Check if protected by OpenZeppelin's initializer modifier
      const hasInitModifier = func.modifiers.some((m) =>
        this.INIT_MODIFIERS.has(m.toLowerCase())
      );

      // Check if guarded by boolean flag e.g. require(!initialized)
      const hasGuardVariable = 
        /require\s*\(\s*!initialized/.test(func.body) ||
        /if\s*\(\s*initialized\s*\)\s*revert/.test(func.body);

      if (!hasInitModifier && !hasGuardVariable) {
        findings.push({
          contractName: contract.name,
          functionName: func.name,
          filePath: contract.filePath,
          line: func.startLine,
          vector: 'SOLIDITY_UNPROTECTED_INITIALIZER',
          severity: 'CRITICAL',
          description: `Function '${func.name}' is an initialization method with ${func.visibility} visibility but lacks OpenZeppelin's 'initializer' modifier or an initialized check.`,
          impact: `An attacker can call '${func.name}()' at any time to re-initialize contract parameters, hijack the 'owner' role, or seize control of the contract proxy.`,
          remediation: `Inherit from OpenZeppelin's 'Initializable' and decorate the function with the 'initializer' modifier, or ensure '_disableInitializers();' is called in the constructor.`,
        });
      }
    }

    return findings;
  }
}
