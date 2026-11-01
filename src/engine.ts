import { BundleExtractor } from './scout/bundle_extractor.js';
import { IdorStriker } from './strikers/idor_striker.js';
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
  candidatesTested: number;
  confirmedReceipts: AshbornReceipt[];
  reports: FormattedReport[];
  durationMs: number;
}

/**
 * ASHBORN NANO-ENGINE
 * Coordinates Scout -> Striker -> Blast Chamber -> Receipt
 */
export class AshbornEngine {
  private chamber: BlastChamber;

  constructor() {
    this.chamber = new BlastChamber({ timeoutMs: 5000 });
  }

  /**
   * Runs an automated dual-token authorization audit against a target scope
   * given its frontend JS bundles or known endpoint list.
   */
  public async auditTargetWithBundles(
    scope: TargetScope,
    jsBundles: string[],
    context: DualSessionContext
  ): Promise<AuditSessionResult> {
    const startTime = performance.now();

    // 1. SCOUT PHASE: Extract all endpoints across bundles
    const allEndpoints: DiscoveredEndpoint[] = [];
    for (let i = 0; i < jsBundles.length; i++) {
      const endpoints = BundleExtractor.extractEndpoints(jsBundles[i], `bundle_${i + 1}.js`);
      allEndpoints.push(...endpoints);
    }

    // 2. FILTER PHASE: Pinpoint high-value targets (ID & mutation parameters)
    const highValueEndpoints = BundleExtractor.filterHighValueTargets(allEndpoints);

    // 3. STRIKER & BLAST CHAMBER PHASE: Generate candidates and test
    const confirmedReceipts: AshbornReceipt[] = [];
    const reports: FormattedReport[] = [];
    let candidatesTested = 0;

    for (const ep of highValueEndpoints) {
      const candidates = IdorStriker.generateCandidates(ep, scope.baseUrl, context);
      for (const candidate of candidates) {
        candidatesTested++;
        const { result, receipt } = await this.chamber.executeCandidate(candidate);

        if (result.passed && receipt) {
          confirmedReceipts.push(receipt);
          const report = ReportGenerator.generateHackerOneReport(receipt);
          reports.push(report);
        }
      }
    }

    const durationMs = Number((performance.now() - startTime).toFixed(2));

    return {
      scope,
      endpointsScanned: allEndpoints.length,
      highValueTargets: highValueEndpoints.length,
      candidatesTested,
      confirmedReceipts,
      reports,
      durationMs,
    };
  }
}
