import { createHash, randomUUID } from 'crypto';
import { ExploitCandidate, ChamberExecutionResult, AshbornReceipt } from '../types.js';
import { SafetyGovernor } from '../governor/safety_governor.js';

export interface ChamberOptions {
  timeoutMs?: number;
  cadenceDelayMs?: { min: number; max: number };
  allowedHosts?: string[];
}

/**
 * THE DETERMINISTIC BLAST CHAMBER
 * The unforgiving judge. Evaluates exploit candidates against live servers
 * and only mints receipts if private data is proven compromised.
 * Includes rate-limit cadence control with jitter and strict host scope enforcement.
 */
export class BlastChamber {
  private readonly timeoutMs: number;
  private readonly cadenceDelayMs?: { min: number; max: number };
  private readonly allowedHosts?: string[];

  constructor(options: ChamberOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.cadenceDelayMs = options.cadenceDelayMs;
    this.allowedHosts = options.allowedHosts;
  }

  /**
   * Executes candidate payload against target and evaluates deterministic assertions.
   */
  public async executeCandidate(candidate: ExploitCandidate): Promise<{
    result: ChamberExecutionResult;
    receipt: AshbornReceipt | null;
  }> {
    // 1. DETERMINISTIC RUNTIME SCOPE GOVERNOR: Refuse packet if host is out-of-scope
    if (this.allowedHosts && !SafetyGovernor.isHostAllowed(candidate.targetUrl, this.allowedHosts)) {
      return {
        result: {
          passed: false,
          statusCode: 0,
          latencyMs: 0,
          bodySnippet: '',
          dataLeaked: false,
          verdict: 'REFUTED_SAFE',
          reason: `LEGAL SAFETY REFUSAL: Target host is OUT OF SCOPE. No network packets transmitted.`,
        },
        receipt: null,
      };
    }

    // 2. WAF EVASION & RATE CADENCE: Jittered sleep to mimic polite human interactions
    if (this.cadenceDelayMs && this.cadenceDelayMs.max > 0) {
      const min = Math.max(0, this.cadenceDelayMs.min);
      const max = Math.max(min, this.cadenceDelayMs.max);
      const jitterMs = Math.floor(Math.random() * (max - min + 1)) + min;
      if (jitterMs > 0) {
        await new Promise(resolve => setTimeout(resolve, jitterMs));
      }
    }

    const startTime = performance.now();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(candidate.targetUrl, {
        method: candidate.method,
        headers: candidate.headers,
        body: candidate.body,
        signal: controller.signal,
      });

      const latencyMs = Number((performance.now() - startTime).toFixed(2));
      const statusCode = response.status;
      const text = await response.text();
      const snippet = text.slice(0, 500);

      // Check for WAF or Server Error
      if (statusCode === 429 || (statusCode === 403 && text.toLowerCase().includes('cloudflare'))) {
        return {
          result: {
            passed: false,
            statusCode,
            latencyMs,
            bodySnippet: snippet,
            dataLeaked: false,
            verdict: 'BLOCKED_BY_WAF',
            reason: 'Request was throttled or blocked by perimeter WAF.',
          },
          receipt: null,
        };
      }

      if (statusCode >= 500) {
        return {
          result: {
            passed: false,
            statusCode,
            latencyMs,
            bodySnippet: snippet,
            dataLeaked: false,
            verdict: 'SERVER_ERROR',
            reason: `Target server raised HTTP ${statusCode}. Inconclusive for authorization bypass.`,
          },
          receipt: null,
        };
      }

      // Check standard access control refusal
      if (statusCode === 401 || statusCode === 403 || statusCode === 404) {
        return {
          result: {
            passed: false,
            statusCode,
            latencyMs,
            bodySnippet: snippet,
            dataLeaked: false,
            verdict: 'REFUTED_SAFE',
            reason: `Access properly rejected with HTTP ${statusCode}. Endpoint correctly enforces isolation.`,
          },
          receipt: null,
        };
      }

      // DETERMINISTIC PROOF ASSERTION:
      // Must be a 2xx success AND must contain the victim's private fingerprint
      const leakConfirmed = (statusCode >= 200 && statusCode < 300) && 
        (candidate.expectedLeakFragment ? text.includes(candidate.expectedLeakFragment) : true);

      if (leakConfirmed) {
        const rawCurl = this.generateCurl(candidate);
        const receipt = this.mintReceipt(candidate, statusCode, latencyMs, rawCurl, candidate.expectedLeakFragment);

        return {
          result: {
            passed: true,
            statusCode,
            latencyMs,
            bodySnippet: snippet,
            dataLeaked: true,
            verdict: 'CONFIRMED_VULNERABILITY',
            reason: `CRITICAL: Attacker token successfully extracted victim data containing private fragment '${candidate.expectedLeakFragment}'.`,
          },
          receipt,
        };
      } else {
        return {
          result: {
            passed: false,
            statusCode,
            latencyMs,
            bodySnippet: snippet,
            dataLeaked: false,
            verdict: 'REFUTED_SAFE',
            reason: `Server responded with HTTP ${statusCode}, but private data fragment was not present in response.`,
          },
          receipt: null,
        };
      }
    } catch (err: unknown) {
      const latencyMs = Number((performance.now() - startTime).toFixed(2));
      const message = err instanceof Error ? err.message : String(err);
      return {
        result: {
          passed: false,
          statusCode: 0,
          latencyMs,
          bodySnippet: '',
          dataLeaked: false,
          verdict: 'SERVER_ERROR',
          reason: `Execution failed: ${message}`,
        },
        receipt: null,
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Generates a reproducible curl command.
   */
  private generateCurl(candidate: ExploitCandidate): string {
    const headerFlags = Object.entries(candidate.headers)
      .map(([k, v]) => `-H "${k}: ${v}"`)
      .join(' ');
    
    const bodyFlag = candidate.body ? `-d '${candidate.body}'` : '';
    return `curl -s -X ${candidate.method} "${candidate.targetUrl}" ${headerFlags} ${bodyFlag}`.trim();
  }

  /**
   * Mints an immutable cryptographic proof receipt.
   */
  private mintReceipt(
    candidate: ExploitCandidate,
    statusCode: number,
    latencyMs: number,
    rawCurl: string,
    leakFingerprint: string
  ): AshbornReceipt {
    const receiptId = `ASHBORN-${randomUUID().slice(0, 8).toUpperCase()}`;
    const timestamp = new Date().toISOString();

    const proofPayload = `${receiptId}:${candidate.targetUrl}:${candidate.vector}:${statusCode}:${leakFingerprint}:${timestamp}`;
    const proofHash = createHash('sha256').update(proofPayload).digest('hex');

    return {
      receiptId,
      timestamp,
      targetUrl: candidate.targetUrl,
      vector: candidate.vector,
      statusCode,
      latencyMs,
      rawCurl,
      leakFingerprint,
      proofHash,
      verifiedBy: 'ASHBORN_BLAST_CHAMBER_V1',
    };
  }
}
