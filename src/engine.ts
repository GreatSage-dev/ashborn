import { BundleExtractor } from './scout/bundle_extractor.js';
import { OpenApiParser, OpenApiSchema } from './scout/openapi_parser.js';
import { CurlParser } from './scout/curl_parser.js';
import { TargetLedger } from './storage/target_ledger.js';
import { HaddixMatrix } from './engine/haddix_matrix.js';
import { IdorStriker } from './strikers/idor_striker.js';
import { MassAssignmentStriker } from './strikers/mass_assignment_striker.js';
import { SafetyGovernor } from './governor/safety_governor.js';
import { BlastChamber } from './chamber/blast_chamber.js';
import { ReportGenerator } from './reporter/markdown_receipt.js';
import { 
  TargetScope, 
  DualSessionContext, 
  DiscoveredEndpoint, 
  AshbornReceipt, 
  FormattedReport 
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
   * Core execution pipeline with Safety Governor, Haddix Matrix, and Target Ledger.
   */
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

