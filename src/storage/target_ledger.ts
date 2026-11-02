import * as fs from 'fs';
import * as path from 'path';
import { AshbornReceipt, DiscoveredEndpoint, FormattedReport } from '../types.js';

export interface TargetMetadata {
  programName: string;
  baseUrl: string;
  createdAt: string;
  lastAuditedAt: string;
  totalEndpoints: number;
  totalFindings: number;
}

/**
 * TARGET FILESYSTEM LEDGER
 * Inspired by Lostsec (Coffinxp) Target Workspace Standard.
 * Organizes targets, endpoints, requests, and verified receipts on disk.
 */
export class TargetLedger {
  private baseDir: string;

  constructor(baseDir = 'targets') {
    const isServerless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
    const root = isServerless ? '/tmp' : process.cwd();
    this.baseDir = path.resolve(root, baseDir);
    if (!fs.existsSync(this.baseDir)) {
      try {
        fs.mkdirSync(this.baseDir, { recursive: true });
      } catch {}
    }
  }

  /**
   * Initializes or returns the directory structure for a specific target program.
   */
  public initTarget(programName: string, baseUrl: string): string {
    const sanitized = programName.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase();
    const targetDir = path.join(this.baseDir, sanitized);

    const subdirs = ['javascript', 'requests', 'receipts'];
    for (const sub of subdirs) {
      const fullPath = path.join(targetDir, sub);
      if (!fs.existsSync(fullPath)) {
        try {
          fs.mkdirSync(fullPath, { recursive: true });
        } catch {}
      }
    }

    const metaPath = path.join(targetDir, 'metadata.json');
    if (!fs.existsSync(metaPath)) {
      const meta: TargetMetadata = {
        programName,
        baseUrl,
        createdAt: new Date().toISOString(),
        lastAuditedAt: new Date().toISOString(),
        totalEndpoints: 0,
        totalFindings: 0,
      };
      try {
        fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2), 'utf-8');
      } catch {}
    }

    return targetDir;
  }

  /**
   * Saves discovered endpoints to endpoints.json.
   */
  public saveEndpoints(programName: string, endpoints: DiscoveredEndpoint[]): void {
    const targetDir = this.initTarget(programName, '');
    const filePath = path.join(targetDir, 'endpoints.json');

    let existing: DiscoveredEndpoint[] = [];
    if (fs.existsSync(filePath)) {
      try {
        existing = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      } catch {}
    }

    // Deduplicate by path + method
    const seen = new Set(existing.map(e => `${e.method}:${e.path}`));
    for (const ep of endpoints) {
      const key = `${ep.method}:${ep.path}`;
      if (!seen.has(key)) {
        seen.add(key);
        existing.push(ep);
      }
    }

    fs.writeFileSync(filePath, JSON.stringify(existing, null, 2), 'utf-8');
    this.updateMetadata(programName, { totalEndpoints: existing.length });
  }

  /**
   * Records a confirmed vulnerability receipt and checks for deduplication.
   * Returns true if newly recorded, false if it was already known (duplicate).
   */
  public recordReceipt(programName: string, receipt: AshbornReceipt, report?: FormattedReport): boolean {
    const targetDir = this.initTarget(programName, '');
    const findingsLog = path.join(targetDir, 'findings.jsonl');
    const receiptsDir = path.join(targetDir, 'receipts');

    // 1. Deduplication check against findingHash
    const knownHashes = this.getKnownFindingHashes(programName);
    if (knownHashes.has(receipt.findingHash)) {
      return false; // Duplicate finding!
    }

    // 2. Append to findings.jsonl
    const line = JSON.stringify({
      timestamp: receipt.timestamp,
      findingHash: receipt.findingHash,
      receiptId: receipt.receiptId,
      vector: receipt.vector,
      targetUrl: receipt.targetUrl,
      proofHash: receipt.proofHash,
      severity: report?.severity || 'HIGH',
    }) + '\n';
    fs.appendFileSync(findingsLog, line, 'utf-8');

    // 3. Write individual receipt file
    const receiptFile = path.join(receiptsDir, `${receipt.receiptId}.json`);
    fs.writeFileSync(receiptFile, JSON.stringify(receipt, null, 2), 'utf-8');

    // 4. Update metadata
    knownHashes.add(receipt.findingHash);
    this.updateMetadata(programName, { 
      totalFindings: knownHashes.size,
      lastAuditedAt: new Date().toISOString()
    });

    return true;
  }

  /**
   * Retrieves all known finding hashes for deduplication.
   */
  public getKnownFindingHashes(programName: string): Set<string> {
    const sanitized = programName.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase();
    const findingsLog = path.join(this.baseDir, sanitized, 'findings.jsonl');
    const hashes = new Set<string>();

    if (fs.existsSync(findingsLog)) {
      const lines = fs.readFileSync(findingsLog, 'utf-8').split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          if (parsed.findingHash) {
            hashes.add(parsed.findingHash);
          }
        } catch {}
      }
    }

    return hashes;
  }

  /**
   * Lists all tracked targets.
   */
  public listTargets(): TargetMetadata[] {
    if (!fs.existsSync(this.baseDir)) return [];
    const entries = fs.readdirSync(this.baseDir, { withFileTypes: true });
    const list: TargetMetadata[] = [];

    for (const ent of entries) {
      if (ent.isDirectory()) {
        const metaPath = path.join(this.baseDir, ent.name, 'metadata.json');
        if (fs.existsSync(metaPath)) {
          try {
            list.push(JSON.parse(fs.readFileSync(metaPath, 'utf-8')));
          } catch {}
        }
      }
    }

    return list;
  }

  private updateMetadata(programName: string, patch: Partial<TargetMetadata>): void {
    const sanitized = programName.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase();
    const metaPath = path.join(this.baseDir, sanitized, 'metadata.json');
    if (fs.existsSync(metaPath)) {
      try {
        const current: TargetMetadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
        const updated = { ...current, ...patch };
        fs.writeFileSync(metaPath, JSON.stringify(updated, null, 2), 'utf-8');
      } catch {}
    }
  }
}
