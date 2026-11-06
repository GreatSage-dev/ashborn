import { SolidityContract, SolidityFunction } from '../types.js';

/**
 * SOLIDITY SCOUT (AST & Grammar Parser)
 * Zero-dependency, sub-millisecond Solidity parser for smart contracts.
 * Extracts contracts, inheritance, state variables, modifiers, and functions.
 */
export class SolidityScout {
  /**
   * Parse a single Solidity source file or contract text.
   */
  public static parseSource(sourceCode: string, filePath = 'Contract.sol'): SolidityContract[] {
    const contracts: SolidityContract[] = [];

    // Strip comments while preserving line count for accurate line reporting
    const sanitized = this.stripCommentsPreservingLines(sourceCode);

    // Regex to match contract / interface / library / abstract contract
    const contractRegex = /(?:(abstract)\s+)?(contract|interface|library)\s+([a-zA-Z0-9_]+)(?:\s+is\s+([^{]+))?\s*\{/g;

    let match: RegExpExecArray | null;
    while ((match = contractRegex.exec(sanitized)) !== null) {
      const isAbstract = !!match[1];
      const rawKind = match[2];
      const kind = isAbstract ? 'abstract' : (rawKind as 'contract' | 'interface' | 'library');
      const contractName = match[3];
      const inheritanceRaw = match[4] || '';
      const inheritance = inheritanceRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

      const contractStartIndex = match.index;
      const bodyStartIndex = contractRegex.lastIndex;
      const bodyEndIndex = this.findMatchingBrace(sanitized, bodyStartIndex - 1);

      if (bodyEndIndex === -1) continue;

      const contractBody = sanitized.substring(bodyStartIndex, bodyEndIndex);
      const rawContractSource = sourceCode.substring(contractStartIndex, bodyEndIndex + 1);

      // Extract state variables
      const stateVariables = this.extractStateVariables(contractBody);

      // Extract custom modifiers defined in this contract
      const modifiers = this.extractDefinedModifiers(contractBody);

      // Extract functions
      const functions = this.extractFunctions(contractBody, sourceCode, bodyStartIndex);

      contracts.push({
        name: contractName,
        kind,
        inheritance,
        stateVariables,
        functions,
        modifiers,
        filePath,
        rawSource: rawContractSource,
      });

      // Move past this contract body
      contractRegex.lastIndex = bodyEndIndex + 1;
    }

    return contracts;
  }

  /**
   * Replace comments with whitespace and newlines to preserve exact line numbering.
   */
  private static stripCommentsPreservingLines(src: string): string {
    return src.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, (match) => {
      // Replace block comment characters with spaces, keeping newlines
      return match.replace(/[^\r\n]/g, ' ');
    });
  }

  /**
   * Find index of closing brace matching the opening brace at openIndex.
   */
  private static findMatchingBrace(str: string, openIndex: number): number {
    let depth = 0;
    for (let i = openIndex; i < str.length; i++) {
      if (str[i] === '{') depth++;
      else if (str[i] === '}') {
        depth--;
        if (depth === 0) return i;
      }
    }
    return -1;
  }

  /**
   * Extract state variables defined at contract root level.
   */
  private static extractStateVariables(contractBody: string): Array<{ name: string; type: string; visibility: string }> {
    const vars: Array<{ name: string; type: string; visibility: string }> = [];
    // Match common state variables e.g. "address public owner;", "mapping(address => uint256) public balances;"
    const lines = contractBody.split(';');
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.includes('function ') || line.includes('modifier ') || line.includes('event ') || line.includes('struct ')) {
        continue;
      }

      // Check if it's a variable declaration
      const varMatch = line.match(/^([a-zA-Z0-9_]+(?:\s*\([^)]*\))?(?:\[\])?(?:\s*=>\s*[a-zA-Z0-9_()]+)?)\s+(public|private|internal|constant|immutable)*\s*([a-zA-Z0-9_]+)(?:\s*=.*)?$/);
      if (varMatch) {
        vars.push({
          type: varMatch[1].trim(),
          visibility: varMatch[2] || 'internal',
          name: varMatch[3].trim(),
        });
      }
    }
    return vars;
  }

  /**
   * Extract modifier names defined in this contract.
   */
  private static extractDefinedModifiers(contractBody: string): string[] {
    const mods: string[] = [];
    const modRegex = /modifier\s+([a-zA-Z0-9_]+)\s*\(/g;
    let m: RegExpExecArray | null;
    while ((m = modRegex.exec(contractBody)) !== null) {
      mods.push(m[1]);
    }
    return mods;
  }

  /**
   * Extract functions and their signature, visibility, modifiers, and body.
   */
  private static extractFunctions(contractBody: string, fullSource: string, bodyOffset: number): SolidityFunction[] {
    const functions: SolidityFunction[] = [];
    // Matches function, constructor, receive, fallback
    const funcHeaderRegex = /(?:function\s+([a-zA-Z0-9_]+)|constructor|receive|fallback)\s*\(([^)]*)\)\s*([^{;]*)(?:\{|;)/g;

    let match: RegExpExecArray | null;
    while ((match = funcHeaderRegex.exec(contractBody)) !== null) {
      const funcName = match[1] || (match[0].startsWith('constructor') ? 'constructor' : match[0].startsWith('receive') ? 'receive' : 'fallback');
      const paramsRaw = match[2] || '';
      const params = paramsRaw.split(',').map((p) => p.trim()).filter(Boolean);
      const attributesRaw = match[3] || '';

      // Determine visibility
      let visibility: 'public' | 'external' | 'internal' | 'private' = 'public';
      if (/\bexternal\b/.test(attributesRaw)) visibility = 'external';
      else if (/\bpublic\b/.test(attributesRaw)) visibility = 'public';
      else if (/\binternal\b/.test(attributesRaw)) visibility = 'internal';
      else if (/\bprivate\b/.test(attributesRaw)) visibility = 'private';
      else if (funcName === 'constructor') visibility = 'public';

      // State mutability
      let stateMutability: 'pure' | 'view' | 'payable' | 'nonpayable' = 'nonpayable';
      if (/\bpayable\b/.test(attributesRaw)) stateMutability = 'payable';
      else if (/\bview\b/.test(attributesRaw)) stateMutability = 'view';
      else if (/\bpure\b/.test(attributesRaw)) stateMutability = 'pure';

      // Extract modifiers applied on this function
      const knownKeywords = new Set([
        'public', 'external', 'internal', 'private',
        'view', 'pure', 'payable', 'nonpayable',
        'virtual', 'override'
      ]);
      const modTokens = attributesRaw.match(/[a-zA-Z0-9_]+(?:\([^)]*\))?/g) || [];
      const modifiers = modTokens
        .map((t) => t.replace(/\(.*?\)/, '').trim())
        .filter((t) => !knownKeywords.has(t) && t !== 'returns');

      // Find function body if it has one (not an interface / abstract signature ending with ';')
      let body = '';
      let rawSource = match[0];
      const matchIndexInFull = bodyOffset + match.index;
      const startLine = fullSource.substring(0, matchIndexInFull).split('\n').length;

      const endsWithBrace = match[0].endsWith('{');
      if (endsWithBrace) {
        const funcBodyStartIndex = funcHeaderRegex.lastIndex;
        const funcBodyEndIndex = this.findMatchingBrace(contractBody, funcBodyStartIndex - 1);
        if (funcBodyEndIndex !== -1) {
          body = contractBody.substring(funcBodyStartIndex, funcBodyEndIndex);
          rawSource = contractBody.substring(match.index, funcBodyEndIndex + 1);
          funcHeaderRegex.lastIndex = funcBodyEndIndex + 1;
        }
      }

      functions.push({
        name: funcName,
        visibility,
        stateMutability,
        modifiers,
        parameters: params,
        body,
        rawSource,
        startLine,
      });
    }

    return functions;
  }
}
