import { AshbornReceipt, FormattedReport } from '../types.js';

/**
 * REPORT GENERATOR MODULE
 * Converts verified Blast Chamber receipts into professional HackerOne / Bugcrowd markdown reports.
 */
export class ReportGenerator {
  public static generateHackerOneReport(receipt: AshbornReceipt): FormattedReport {
    const isIdor = receipt.vector.startsWith('IDOR');
    const isMassAssignment = receipt.vector === 'MASS_ASSIGNMENT_VIOLATION';
    const isJwt = receipt.vector.startsWith('JWT');

    let title: string;
    let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    let vulnerabilityClass: string;
    let impact: string;
    let remediation: string;

    const pathname = new URL(receipt.targetUrl).pathname;

    if (isIdor) {
      title = `Broken Object Level Authorization (BOLA/IDOR) on ${pathname}`;
      severity = 'HIGH';
      vulnerabilityClass = 'CWE-639: Authorization Bypass Through User-Controlled Key';
      impact = 'An attacker possessing any standard user account can enumerate and extract private records belonging to any other user on the platform without authorization.';
      remediation = 'Implement strict server-side authorization checks verifying that the authenticated session identity strictly owns the requested resource ID before fulfilling the request.';
    } else if (isMassAssignment) {
      title = `Mass Assignment / Broken Object Property Level Authorization on ${pathname}`;
      severity = 'HIGH';
      vulnerabilityClass = 'CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes';
      impact = 'An unprivileged user can modify protected object attributes (such as role or administrative flags) by supplying unexpected keys in state-modifying requests.';
      remediation = 'Use strict Data Transfer Object (DTO) schema validation or explicit field whitelisting to reject unexpected client-supplied properties.';
    } else {
      title = `Authentication Bypass via JWT Misconfiguration on ${pathname}`;
      severity = 'CRITICAL';
      vulnerabilityClass = 'CWE-347: Improper Verification of Cryptographic Signature';
      impact = 'An attacker can forge or tamper with session tokens to bypass authentication and assume administrative privileges across the application.';
      remediation = 'Ensure the backend JWT library strictly enforces signature verification and explicitly rejects the none algorithm.';
    }

    const stepsToReproduce = [
      `1. Log in as an authenticated user and obtain an active session token.`,
      `2. Identify the target endpoint at \`${pathname}\`.`,
      `3. Transmit the attached Proof-of-Concept curl command.`,
      `4. Observe that the server returns HTTP ${receipt.statusCode} demonstrating unexpected parameter processing or unauthorized access.`,
    ].join('\n');

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
    const forensicDetails = report.tamperProofReceipt.forensicBinding ? `
- **Finding Fingerprint (Deduplication Hash):** \`${report.tamperProofReceipt.findingHash}\`
- **Request Hash:** \`${report.tamperProofReceipt.forensicBinding.requestHeadersHash.slice(0, 16)}...\`
- **Response Body Hash:** \`${report.tamperProofReceipt.forensicBinding.responseBodyHash.slice(0, 16)}...\`
- **Authorized Scope Host:** \`${report.tamperProofReceipt.forensicBinding.scopeHost}\`` : '';

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
- **Timestamp:** \`${report.tamperProofReceipt.timestamp}\`${forensicDetails}
- **SHA-256 Forensic Seal:** \`${report.tamperProofReceipt.proofHash}\`
- **Verified By:** \`${report.tamperProofReceipt.verifiedBy}\`
`;
  }
}
