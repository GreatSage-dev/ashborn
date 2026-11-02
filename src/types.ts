/**
 * ASHBORN CORE TYPES
 * First-Principles Data Contracts for the Autonomous Hunter
 */

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export type AttackVector = 
  | 'IDOR_READ_VIOLATION'
  | 'IDOR_MUTATE_VIOLATION'
  | 'JWT_ALG_NONE_BYPASS'
  | 'JWT_SIGNATURE_STRIPPED'
  | 'MASS_ASSIGNMENT_VIOLATION';

export interface TargetScope {
  name: string;
  baseUrl: string;
  allowedHosts: string[];
  rulesOfEngagement: string;
  outOfScopePatterns?: RegExp[];
}

export interface DiscoveredEndpoint {
  path: string;
  method: HttpMethod;
  parameters: string[];
  isStateMutating: boolean;
  sourceBundle?: string;
}

export interface DualSessionContext {
  victimToken: string;
  victimResourceId: string;
  victimSecretIdentifier?: string; // Optional manual fingerprint; if omitted, differential testing auto-extracts it from User A's baseline
  attackerToken: string;
}

export interface ExploitCandidate {
  vector: AttackVector;
  targetUrl: string;
  method: HttpMethod;
  headers: Record<string, string>;
  body?: string;
  baselineHeaders?: Record<string, string>; // User A (victim) headers for two-sided differential comparison
  baselineBody?: string;
  expectedLeakFragment?: string;
}

export interface DifferentialEvidence {
  baselineStatus: number;
  probeStatus: number;
  leakedFields: string[];
  byteDifference: number;
}

export interface ChamberExecutionResult {
  passed: boolean;
  statusCode: number;
  latencyMs: number;
  bodySnippet: string;
  dataLeaked: boolean;
  verdict: 'CONFIRMED_VULNERABILITY' | 'REFUTED_SAFE' | 'BLOCKED_BY_WAF' | 'SERVER_ERROR';
  reason: string;
  differentialEvidence?: DifferentialEvidence;
}

export interface ForensicBinding {
  requestMethod: HttpMethod;
  requestUrl: string;
  requestHeadersHash: string;
  requestBodyHash: string;
  responseStatus: number;
  responseBodyHash: string;
  scopeHost: string;
}

export interface AshbornReceipt {
  receiptId: string;
  findingHash: string; // Deduplication fingerprint: SHA256(canonicalHost:normalizedPath:vector)
  timestamp: string;
  targetUrl: string;
  vector: AttackVector;
  statusCode: number;
  latencyMs: number;
  rawCurl: string;
  leakFingerprint: string;
  proofHash: string; // Cryptographic seal over all forensic properties
  verifiedBy: 'ASHBORN_BLAST_CHAMBER_V1';
  differentialProof?: DifferentialEvidence;
  forensicBinding?: ForensicBinding;
}

export interface FormattedReport {
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  vulnerabilityClass: string;
  summary: string;
  stepsToReproduce: string;
  proofOfConceptCurl: string;
  impact: string;
  remediation: string;
  tamperProofReceipt: AshbornReceipt;
}
