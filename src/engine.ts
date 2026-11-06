import { BundleExtractor } from './scout/bundle_extractor.js';
import { OpenApiParser, OpenApiSchema } from './scout/openapi_parser.js';
import { PostmanParser, PostmanCollection } from './scout/postman_parser.js';
import { GraphQLParser } from './scout/graphql_parser.js';
import { GraphQLStriker } from './strikers/graphql_striker.js';
import { CurlParser } from './scout/curl_parser.js';
import { TargetLedger } from './storage/target_ledger.js';
import { HaddixMatrix } from './engine/haddix_matrix.js';
import { IdorStriker } from './strikers/idor_striker.js';
import { MassAssignmentStriker } from './strikers/mass_assignment_striker.js';
import { SafetyGovernor } from './governor/safety_governor.js';
import { BlastChamber } from './chamber/blast_chamber.js';
import { ReportGenerator } from './reporter/markdown_receipt.js';
import { SolidityScout } from './scout/solidity_scout.js';
import { SolidityAccessStriker } from './strikers/solidity_access_striker.js';
import { SolidityReentrancyStriker } from './strikers/solidity_reentrancy_striker.js';
import { SolidityProxyStriker } from './strikers/solidity_proxy_striker.js';
import { FoundryPocGenerator } from './reporter/foundry_poc_generator.js';
import { 
  TargetScope, 
  DualSessionContext, 
  DiscoveredEndpoint, 
  AshbornReceipt, 
  FormattedReport,
  SolidityFinding
} from './types.js';

export interface AuditSessionResult {
  scope: TargetScope;
  endpointsScanned: number;
  highValueTargets: number;
  blockedByGovernor: number;
  candidatesTested: number;
  confirmedReceipts: AshbornReceipt[];
  reports: FormattedReport[];
  durationMs: number;
}

export interface EngineOptions {
  timeoutMs?: number;
  cadenceDelayMs?: { min: number; max: number };
  ledgerBaseDir?: string;
  enableHaddixMatrix?: boolean;
}

/**
 * ASHBORN NANO-ENGINE
 * Coordinates Scout -> Safety Governor -> Striker -> Blast Chamber -> Receipt -> Ledger
 */
export class AshbornEngine {
  private options: EngineOptions;
  private ledger: TargetLedger;

  constructor(options: EngineOptions = {}) {
    this.options = options;
    this.ledger = new TargetLedger(options.ledgerBaseDir || 'targets');
  }

  /**
   * INGRESS 1: Runs an audit using raw 'Copy as cURL' commands for User A and User B.
   * Extracts authorization, cookies, CSRF tokens, and target path automatically.
   */
  public async auditTargetWithCurls(
    userACurl: string,
    userBCurl: string,
    programName?: string
  ): Promise<AuditSessionResult> {
    const { context, scope, primaryCurl } = CurlParser.buildDualContextFromCurls(userACurl, userBCurl);
    const targetProgram = programName || scope.name;

    const endpoint: DiscoveredEndpoint = {
      path: primaryCurl.path,
      method: primaryCurl.method,
      parameters: primaryCurl.extractedResourceId ? ['id'] : [],
      isStateMutating: ['POST', 'PUT', 'PATCH', 'DELETE'].includes(primaryCurl.method),
      sourceBundle: 'curl_ingress',
    };

    return this.executeAudit(scope, [endpoint], context, targetProgram);
  }

  /**
   * INGRESS 2: Runs an audit using extracted client-side JS bundles.
   */
  public async auditTargetWithBundles(
    scope: TargetScope,
    jsBundles: string[],
    context: DualSessionContext,
    programName?: string
  ): Promise<AuditSessionResult> {
    const allEndpoints: DiscoveredEndpoint[] = [];
    for (let i = 0; i < jsBundles.length; i++) {
      const endpoints = BundleExtractor.extractEndpoints(jsBundles[i], `bundle_${i + 1}.js`);
      allEndpoints.push(...endpoints);
    }

    return this.executeAudit(scope, allEndpoints, context, programName);
  }

  /**
   * INGRESS 3: Runs an audit using an OpenAPI/Swagger schema.
   */
  public async auditTargetWithOpenApi(
    scope: TargetScope,
    schema: string | OpenApiSchema,
    context: DualSessionContext,
    programName?: string
  ): Promise<AuditSessionResult> {
    const endpoints = OpenApiParser.parseSchema(schema);
    return this.executeAudit(scope, endpoints, context, programName);
  }

  /**
   * INGRESS 4: Runs an audit using an exported Postman Collection (v2.0 or v2.1).
   */
  public async auditTargetWithPostman(
    scope: TargetScope,
    collection: string | PostmanCollection,
    context: DualSessionContext,
    programName?: string
  ): Promise<AuditSessionResult> {
    const endpoints = PostmanParser.parseCollection(collection);
    return this.executeAudit(scope, endpoints, context, programName);
  }

  /**
   * INGRESS 5: Runs an audit against a GraphQL endpoint via introspection or schema.
   */
  public async auditTargetWithGraphQL(
    scope: TargetScope,
    graphqlPath: string,
    introspectionData: string | Record<string, unknown>,
    context: DualSessionContext,
    programName?: string
  ): Promise<AuditSessionResult> {
    const startTime = performance.now();
    const targetProgram = programName || scope.name;
    const summary = GraphQLParser.parseSchema(introspectionData);

    const fullUrl = `${scope.baseUrl.replace(/\/$/, '')}/${graphqlPath.replace(/^\//, '')}`;
    const chamber = new BlastChamber({
      timeoutMs: this.options.timeoutMs ?? 5000,
      cadenceDelayMs: this.options.cadenceDelayMs,
      allowedHosts: scope.allowedHosts,
    });

    const confirmedReceipts: AshbornReceipt[] = [];
    const reports: FormattedReport[] = [];
    let candidatesTested = 0;
    let blockedByGovernor = 0;

    // Test queries with object ID arguments (BOLA)
    const targetQueries = summary.queries.filter(q => q.isObjectTarget);
    for (const q of targetQueries) {
      const candidates = GraphQLStriker.generateQueryCandidates(q, fullUrl, context);
      for (const cand of candidates) {
        const safety = SafetyGovernor.isBlocked(cand.targetUrl, cand.method, scope.outOfScopePatterns, scope.allowedHosts);
        if (safety.blocked) {
          blockedByGovernor++;
          continue;
        }
        candidatesTested++;
        const { result, receipt } = await chamber.executeCandidate(cand);
        if (result.passed && receipt) {
          const isNew = this.ledger.recordReceipt(targetProgram, receipt);
          if (isNew) {
            confirmedReceipts.push(receipt);
            reports.push(ReportGenerator.generateHackerOneReport(receipt));
          }
        }
      }
    }

    const durationMs = Number((performance.now() - startTime).toFixed(2));
    return {
      scope,
      endpointsScanned: summary.queries.length + summary.mutations.length,
      highValueTargets: targetQueries.length,
      blockedByGovernor,
      candidatesTested,
      confirmedReceipts,
      reports,
      durationMs,
    };
  }

  /**
   * Core execution pipeline with Safety Governor, Haddix Matrix, and Target Ledger.
   */
  /**
   * INGRESS 6: Smart Contract & Solidity Codebase Audit
   * Analyzes Solidity files for missing access control, reentrancy, and proxy initialization traps.
   * Generates Foundry exploit PoCs conforming to Immunefi & Code4rena standards.
   */
  public auditSoliditySource(
    sources: Array<{ path: string; content: string }>,
    programName = 'smart-contracts'
  ): {
    contractsAnalyzed: number;
    findings: SolidityFinding[];
    durationMs: number;
  } {
    const startTime = performance.now();
    const allFindings: SolidityFinding[] = [];
    let contractsCount = 0;

    for (const source of sources) {
      const contracts = SolidityScout.parseSource(source.content, source.path);
      contractsCount += contracts.length;

      for (const contract of contracts) {
        // Strike 1: Access Control
        const accessFindings = SolidityAccessStriker.strike(contract);
        // Strike 2: Reentrancy (CEI)
        const reentrancyFindings = SolidityReentrancyStriker.strike(contract);
        // Strike 3: Unprotected Initializer
        const proxyFindings = SolidityProxyStriker.strike(contract);

        const combined = [...accessFindings, ...reentrancyFindings, ...proxyFindings];
        for (const finding of combined) {
          finding.foundryPocCode = FoundryPocGenerator.generate(finding);
          allFindings.push(finding);
        }
      }
    }

    const durationMs = Number((performance.now() - startTime).toFixed(2));
    return {
      contractsAnalyzed: contractsCount,
      findings: allFindings,
      durationMs,
    };
  }

  private async executeAudit(
    scope: TargetScope,
    endpoints: DiscoveredEndpoint[],
    context: DualSessionContext,
    programName?: string
  ): Promise<AuditSessionResult> {
    const startTime = performance.now();
    const targetProgram = programName || scope.name;

    // Save discovered endpoints to Target Ledger
    this.ledger.saveEndpoints(targetProgram, endpoints);

    const chamber = new BlastChamber({
      timeoutMs: this.options.timeoutMs ?? 5000,
      cadenceDelayMs: this.options.cadenceDelayMs,
      allowedHosts: scope.allowedHosts,
    });

    let blockedByGovernor = 0;
    const safeEndpoints: DiscoveredEndpoint[] = [];

    // 1. SAFETY & SCOPE GATE: Evaluate 100% of discovered endpoints before filtering
    for (const ep of endpoints) {
      const safety = SafetyGovernor.isBlocked(ep.path, ep.method, scope.outOfScopePatterns, scope.allowedHosts);
      if (safety.blocked) {
        blockedByGovernor++;
      } else {
        safeEndpoints.push(ep);
      }
    }

    const highValueEndpoints = BundleExtractor.filterHighValueTargets(safeEndpoints);
    const confirmedReceipts: AshbornReceipt[] = [];
    const reports: FormattedReport[] = [];
    let candidatesTested = 0;

    for (const ep of highValueEndpoints) {
      // If Haddix Matrix enabled or single endpoint audit, run the 4-stage systematic checklist
      if (this.options.enableHaddixMatrix) {
        const matrixStages = HaddixMatrix.generateMatrix(ep, scope.baseUrl, context, scope);
        for (const stage of matrixStages) {
          const candidateSafety = SafetyGovernor.isBlocked(
            stage.candidate.targetUrl,
            stage.candidate.method,
            scope.outOfScopePatterns,
            scope.allowedHosts
          );
          if (candidateSafety.blocked) {
            blockedByGovernor++;
            continue;
          }

          candidatesTested++;
          const { result, receipt } = await chamber.executeCandidate(stage.candidate);
          if (result.passed && receipt) {
            // Check Target Ledger deduplication
            const isNew = this.ledger.recordReceipt(targetProgram, receipt);
            if (isNew) {
              confirmedReceipts.push(receipt);
              reports.push(ReportGenerator.generateHackerOneReport(receipt));
            }
          }
        }
      } else {
        // Standard IDOR Probes
        const idorCandidates = IdorStriker.generateCandidates(ep, scope.baseUrl, context);
        for (const candidate of idorCandidates) {
          const candidateSafety = SafetyGovernor.isBlocked(candidate.targetUrl, candidate.method, scope.outOfScopePatterns, scope.allowedHosts);
          if (candidateSafety.blocked) {
            blockedByGovernor++;
            continue;
          }

          candidatesTested++;
          const { result, receipt } = await chamber.executeCandidate(candidate);
          if (result.passed && receipt) {
            this.ledger.recordReceipt(targetProgram, receipt);
            confirmedReceipts.push(receipt);
            reports.push(ReportGenerator.generateHackerOneReport(receipt));
          }
        }

        // Standard Mass Assignment Probes (for PUT/PATCH endpoints)
        if (ep.method === 'PUT' || ep.method === 'PATCH') {
          const massAssignCandidates = MassAssignmentStriker.generateCandidates(
            ep,
            scope.baseUrl,
            context.attackerToken,
            context.victimResourceId
          );
          for (const candidate of massAssignCandidates) {
            const candidateSafety = SafetyGovernor.isBlocked(candidate.targetUrl, candidate.method, scope.outOfScopePatterns, scope.allowedHosts);
            if (candidateSafety.blocked) {
              blockedByGovernor++;
              continue;
            }

            candidatesTested++;
            const { result, receipt } = await chamber.executeCandidate(candidate);
            if (result.passed && receipt) {
              this.ledger.recordReceipt(targetProgram, receipt);
              confirmedReceipts.push(receipt);
              reports.push(ReportGenerator.generateHackerOneReport(receipt));
            }
          }
        }
      }
    }

    const durationMs = Number((performance.now() - startTime).toFixed(2));

    return {
      scope,
      endpointsScanned: endpoints.length,
      highValueTargets: highValueEndpoints.length,
      blockedByGovernor,
      candidatesTested,
      confirmedReceipts,
      reports,
      durationMs,
    };
  }
}

