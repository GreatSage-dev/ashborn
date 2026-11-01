import { BundleExtractor } from './scout/bundle_extractor.js';
import { OpenApiParser, OpenApiSchema } from './scout/openapi_parser.js';
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

/**
 * ASHBORN NANO-ENGINE
 * Coordinates Scout -> Safety Governor -> Striker -> Blast Chamber -> Receipt
 */
export class AshbornEngine {
  private chamber: BlastChamber;

  constructor() {
    this.chamber = new BlastChamber({ timeoutMs: 5000 });
  }

  /**
   * Runs an audit using extracted client-side JS bundles.
   */
  public async auditTargetWithBundles(
    scope: TargetScope,
    jsBundles: string[],
    context: DualSessionContext
  ): Promise<AuditSessionResult> {
    const allEndpoints: DiscoveredEndpoint[] = [];
    for (let i = 0; i < jsBundles.length; i++) {
      const endpoints = BundleExtractor.extractEndpoints(jsBundles[i], `bundle_${i + 1}.js`);
      allEndpoints.push(...endpoints);
    }

    return this.executeAudit(scope, allEndpoints, context);
  }

  /**
   * Runs an audit using an OpenAPI/Swagger schema.
   */
  public async auditTargetWithOpenApi(
    scope: TargetScope,
    schema: string | OpenApiSchema,
    context: DualSessionContext
  ): Promise<AuditSessionResult> {
    const endpoints = OpenApiParser.parseSchema(schema);
    return this.executeAudit(scope, endpoints, context);
  }

  /**
   * Core execution pipeline with Safety Governor and Multi-Vector Strikers.
   */
  private async executeAudit(
    scope: TargetScope,
    endpoints: DiscoveredEndpoint[],
    context: DualSessionContext
  ): Promise<AuditSessionResult> {
    const startTime = performance.now();

    const highValueEndpoints = BundleExtractor.filterHighValueTargets(endpoints);
    const confirmedReceipts: AshbornReceipt[] = [];
    const reports: FormattedReport[] = [];
    let candidatesTested = 0;
    let blockedByGovernor = 0;

    for (const ep of highValueEndpoints) {
      // 1. SAFETY GOVERNOR CHECK
      const safety = SafetyGovernor.isBlocked(ep.path, ep.method, scope.outOfScopePatterns);
      if (safety.blocked) {
        blockedByGovernor++;
        continue;
      }

      // 2. IDOR PROBES
      const idorCandidates = IdorStriker.generateCandidates(ep, scope.baseUrl, context);
      for (const candidate of idorCandidates) {
        candidatesTested++;
        const { result, receipt } = await this.chamber.executeCandidate(candidate);
        if (result.passed && receipt) {
          confirmedReceipts.push(receipt);
          reports.push(ReportGenerator.generateHackerOneReport(receipt));
        }
      }

      // 3. MASS ASSIGNMENT PROBES (for PUT/PATCH endpoints)
      if (ep.method === 'PUT' || ep.method === 'PATCH') {
        const massAssignCandidates = MassAssignmentStriker.generateCandidates(
          ep,
          scope.baseUrl,
          context.attackerToken,
          context.victimResourceId
        );
        for (const candidate of massAssignCandidates) {
          candidatesTested++;
          const { result, receipt } = await this.chamber.executeCandidate(candidate);
          if (result.passed && receipt) {
            confirmedReceipts.push(receipt);
            reports.push(ReportGenerator.generateHackerOneReport(receipt));
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
