import { AshbornReceipt, FormattedReport } from '../types.js';

/**
 * REPORT GENERATOR MODULE
 * Converts verified Blast Chamber receipts into professional HackerOne / Bugcrowd markdown reports.
 */
export class ReportGenerator {
  public static generateHackerOneReport(receipt: AshbornReceipt): FormattedReport {
    const isIdor = receipt.vector.startsWith('IDOR');
    const title = isIdor
      ? `Broken Object Level Authorization (BOLA/IDOR) on ${new URL(receipt.targetUrl).pathname}`
      : `Authentication Bypass via JWT Misconfiguration on ${new URL(receipt.targetUrl).pathname}`;

    const severity = isIdor ? 'HIGH' : 'CRITICAL';
    const vulnerabilityClass = isIdor 
      ? 'CWE-639: Authorization Bypass Through User-Controlled Key'
      : 'CWE-347: Improper Verification of Cryptographic Signature';

    const stepsToReproduce = [
      `1. Log in as regular User B (Attacker) and obtain an active session token.`,
      `2. Identify private resource owned by User A (Victim) with identifier containing fingerprint \`${receipt.leakFingerprint}\`.`,
      `3. Execute the attached Proof-of-Concept curl command authenticated exclusively with User B's token.`,
      `4. Observe that the server returns HTTP ${receipt.statusCode} containing User A's private data, demonstrating complete cross-tenant boundary failure.`,
    ].join('\n');

    const impact = isIdor
      ? `An attacker possessing any standard user account can enumerate and extract private records belonging to any other user on the platform without authorization.`
      : `An attacker can forge or tamper with session tokens to bypass authentication and assume administrative privileges across the application.`;

    const remediation = isIdor
      ? `Implement strict server-side authorization checks verifying that the authenticated session identity strictly owns the requested resource ID before fulfilling the request.`
      : `Ensure the backend JWT library strictly enforces signature verification and explicitly rejects the 'none' algorithm.`;

    const summary = `During an authorized security assessment, an automated audit by Ashborn verified an unauthenticated cross-tenant data leak on endpoint \`${receipt.targetUrl}\`. The vulnerability was deterministically reproduced in a sandboxed blast chamber with latency ${receipt.latencyMs}ms.`;

    return {
      title,
      severity,
      vulnerabilityClass,
      summary,
      stepsToReproduce,
      proofOfConceptCurl: receipt.rawCurl,
      impact,
      remediation,
      tamperProofReceipt: receipt,
    };
  }

  /**
   * Formats the report as a ready-to-copy Markdown document.
   */
  public static formatMarkdown(report: FormattedReport): string {
    return `# [${report.severity}] ${report.title}

## Vulnerability Classification
- **Type:** ${report.vulnerabilityClass}
- **Severity Rating:** ${report.severity}

## Summary
${report.summary}

## Steps to Reproduce
${report.stepsToReproduce}

## Proof of Concept (Reproducible cURL)
\`\`\`bash
${report.proofOfConceptCurl}
\`\`\`

## Expected Behavior vs Actual Behavior
- **Expected:** Server rejects request with \`HTTP 401 Unauthorized\` or \`HTTP 403 Forbidden\`.
- **Actual:** Server returned \`HTTP ${report.tamperProofReceipt.statusCode}\` and exposed private fingerprint: \`${report.tamperProofReceipt.leakFingerprint}\`.

## Impact
${report.impact}

## Remediation
${report.remediation}

---
### 🛡️ Ashborn Cryptographic Proof Receipt
- **Receipt ID:** \`${report.tamperProofReceipt.receiptId}\`
- **Timestamp:** \`${report.tamperProofReceipt.timestamp}\`
- **SHA-256 Seal:** \`${report.tamperProofReceipt.proofHash}\`
- **Verified By:** \`${report.tamperProofReceipt.verifiedBy}\`
`;
  }
}
