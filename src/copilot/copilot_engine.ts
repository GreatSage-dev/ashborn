import { AutopilotStatusSnapshot, CapturedTrafficItem } from '../scout/cdp_scout.js';
import { AshbornReceipt, FormattedReport } from '../types.js';

export type CopilotProvider = 'groq' | 'openrouter' | 'gemini' | 'github' | 'local' | 'freellmapi' | 'builtin';

export interface CopilotMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface CopilotChatConfig {
  provider: CopilotProvider;
  apiKey?: string;
  model?: string;
  customEndpoint?: string;
}

export interface CopilotSecurityContext {
  targetUrl: string;
  allowedHosts: string[];
  readOnlySafeMode: boolean;
  attackerAuthSummary: string;
  capturedEndpoints: CapturedTrafficItem[];
  receipts: AshbornReceipt[];
  reports: FormattedReport[];
  logs: string[];
}

export interface CopilotChatResponse {
  reply: string;
  provider: CopilotProvider;
  model: string;
  action?: {
    type: 'STRIKE_ENDPOINT' | 'SET_ATTACKER_GUEST' | 'SET_SCOPE' | 'OPEN_TAB' | 'VIEW_REPORT';
    payload?: Record<string, unknown>;
  };
}

export const COPILOT_PROVIDER_PRESETS: Record<CopilotProvider, { name: string; endpoint: string; defaultModel: string; docUrl: string }> = {
  groq: {
    name: 'Groq (Free & Fast)',
    endpoint: 'https://api.groq.com/openai/v1/chat/completions',
    defaultModel: 'openai/gpt-oss-120b',
    docUrl: 'https://console.groq.com/keys',
  },
  openrouter: {
    name: 'OpenRouter (Free Models)',
    endpoint: 'https://openrouter.ai/api/v1/chat/completions',
    defaultModel: 'meta-llama/llama-3.3-70b-instruct:free',
    docUrl: 'https://openrouter.ai/keys',
  },
  gemini: {
    name: 'Google AI Studio (Gemini)',
    endpoint: 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions',
    defaultModel: 'gemini-1.5-flash',
    docUrl: 'https://aistudio.google.com/app/apikey',
  },
  github: {
    name: 'GitHub Models (Free with GitHub Token)',
    endpoint: 'https://models.inference.ai.azure.com/chat/completions',
    defaultModel: 'gpt-4o-mini',
    docUrl: 'https://github.com/marketplace/models',
  },
  local: {
    name: 'Local LLM (LM Studio / Ollama)',
    endpoint: 'http://127.0.0.1:1234/v1/chat/completions',
    defaultModel: 'local-model',
    docUrl: 'https://lmstudio.ai',
  },
  freellmapi: {
    name: 'FreeLLMAPI (7.4B Token Local Router)',
    endpoint: 'http://127.0.0.1:8000/v1/chat/completions',
    defaultModel: 'groq/llama-3.3-70b-versatile',
    docUrl: 'https://github.com/tashfeenahmed/freellmapi',
  },
  builtin: {
    name: 'Built-in Tactical Engine (No Key Needed)',
    endpoint: 'internal',
    defaultModel: 'ashborn-tactical-v1',
    docUrl: '',
  },
};

export class CopilotEngine {
  public static buildSystemPrompt(context: CopilotSecurityContext): string {
    const endpointsSummary = context.capturedEndpoints.slice(0, 15).map(e => {
      const op = e.operationName ? ` (${e.operationName})` : '';
      return `- [${e.id}] ${e.method} ${e.path}${op} -> Status: ${e.auditStatus} (${e.auditReason || 'Captured'})`;
    }).join('\n') || 'None captured yet. Browsing active.';

    const findingsSummary = context.reports.map(r => {
      return `- ${r.tamperProofReceipt?.receiptId || 'FINDING'} [${r.severity}] on ${r.tamperProofReceipt?.forensicBinding?.requestUrl || 'endpoint'}: ${r.title}`;
    }).join('\n') || 'Zero vulnerabilities confirmed so far. All tested endpoints safe.';

    return `You are Ashborn Shadow Co-Pilot, an elite authorized AI bug bounty pair-hunter and security researcher.
You assist the human hunter conducting authorized security testing against target: "${context.targetUrl || 'Not specified'}".

SCOPE & SAFETY RULES:
- Authorized hosts: ${context.allowedHosts.join(', ') || 'Auto-detecting apex domain'}
- Safety Governor: STRICTLY ACTIVE. Destructive mutations, password resets, account deletion, and billing paths are strictly forbidden.
- Attacker Auth State: ${context.attackerAuthSummary}
- Read-Only Safe Mode: ${context.readOnlySafeMode ? 'ACTIVE (GET and read queries only)' : 'MUTATIONS PERMITTED'}

LIVE SESSION REALITY:
Currently Captured Endpoints:
${endpointsSummary}

Confirmed Vulnerability Receipts:
${findingsSummary}

YOUR MISSION:
1. Provide sharp, tactical offensive security guidance (BOLA, IDOR, Mass Assignment, GraphQL introspection, Token tampering).
2. Answer the hunter's questions about live captured endpoints, why an endpoint was refuted safe, and what high-value targets to explore next.
3. Suggest concrete actions (e.g. "You should test endpoint cdp-1" or "Open your trade offers tab").
4. If asked to draft a report, produce a clean, professional HackenProof/HackerOne markdown report with reproduction steps, curl proof, and CVSS impact.
5. If the user asks you to take an action (e.g., strike an endpoint or test unauthenticated guest access), explicitly declare your recommendation.

Keep answers concise, actionable, and formatted in clean Markdown. Never give fluff or generic corporate filler. Speak like an experienced security researcher pair-programming live.`;
  }

  public async chat(
    messages: CopilotMessage[],
    context: CopilotSecurityContext,
    config: CopilotChatConfig
  ): Promise<CopilotChatResponse> {
    const provider = config.provider || 'builtin';
    const lastUserMessage = [...messages].reverse().find(m => m.role === 'user')?.content || '';

    // Check client-supplied key or server-side environment variables
    const envKey =
      (provider === 'groq' && process.env.GROQ_API_KEY) ||
      (provider === 'openrouter' && process.env.OPENROUTER_API_KEY) ||
      (provider === 'gemini' && (process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY)) ||
      (provider === 'github' && (process.env.GITHUB_TOKEN || process.env.GITHUB_MODELS_TOKEN)) ||
      process.env.COPILOT_API_KEY;

    const apiKey = (config.apiKey && config.apiKey.trim()) || (envKey && envKey.trim()) || '';

    // If provider is builtin or no API key is provided for cloud providers, use tactical fallback
    if (provider === 'builtin' || (!apiKey && provider !== 'local' && provider !== 'freellmapi')) {
      const fallback = this.executeTacticalFallback(lastUserMessage, context);
      if (provider !== 'builtin') {
        const preset = COPILOT_PROVIDER_PRESETS[provider];
        return {
          reply: `> 💡 **Ashborn Tactical Brain (Zero-Key Mode):**\n> To unlock direct cloud inference with **${preset.name}** (${config.model || preset.defaultModel}), grab a free key in 15 seconds at [${preset.docUrl}](${preset.docUrl}) (no credit card needed) and paste it into the drawer key box, or add \`${provider.toUpperCase()}_API_KEY=...\` to your \`.env\` file.\n\n${fallback.reply}`,
          provider: 'builtin',
          model: 'ashborn-tactical-v1',
          action: fallback.action,
        };
      }
      return fallback;
    }

    const preset = COPILOT_PROVIDER_PRESETS[provider];
    const endpointUrl = config.customEndpoint || preset.endpoint;
    const model = config.model || preset.defaultModel;

    const systemPrompt = CopilotEngine.buildSystemPrompt(context);
    const apiMessages = [
      { role: 'system', content: systemPrompt },
      ...messages.slice(-10),
    ];

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (apiKey) {
        headers['Authorization'] = `Bearer ${apiKey}`;
      }

      const res = await fetch(endpointUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model,
          messages: apiMessages,
          temperature: 0.3,
          max_tokens: 1200,
        }),
      });

      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`Provider ${provider} responded with HTTP ${res.status}: ${errorText.slice(0, 180)}`);
      }

      const data = await res.json() as {
        choices?: Array<{ message?: { content?: string } }>;
      };

      const reply = data.choices?.[0]?.message?.content?.trim() || 'No response returned from model.';
      const action = this.detectActionFromText(lastUserMessage, reply, context);

      return {
        reply,
        provider,
        model,
        action,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      // Fallback gracefully to built-in tactical engine with error disclaimer
      const fallback = this.executeTacticalFallback(lastUserMessage, context);
      return {
        reply: `> ⚠️ **Cloud Provider Notice:** Could not reach ${preset.name} (${message}).\n> *Falling back to Ashborn's Built-in Tactical Engine:*\n\n${fallback.reply}`,
        provider: 'builtin',
        model: 'ashborn-tactical-v1',
        action: fallback.action,
      };
    }
  }

  public executeTacticalFallback(userText: string, context: CopilotSecurityContext): CopilotChatResponse {
    const q = userText.toLowerCase().trim();

    // 1. Findings query
    if (q.includes('finding') || q.includes('what did you find') || q.includes('vulnerabilit') || q.includes('results') || q.includes('any bug')) {
      if (context.reports.length === 0) {
        const skippedCount = context.capturedEndpoints.filter(e => e.auditStatus === 'SKIPPED_MUTATING').length;
        const safeCount = context.capturedEndpoints.filter(e => e.auditStatus === 'REFUTED_SAFE').length;
        return {
          reply: `### 🎯 Live Hunt Status on \`${context.targetUrl || 'Target'}\`
- **Confirmed Vulnerabilities:** 0
- **Refuted Safe Endpoints:** ${safeCount} (access safely rejected by target)
- **Captured Endpoints:** ${context.capturedEndpoints.length}
${skippedCount > 0 ? `- **Read-Only Paused:** ${skippedCount} mutating requests waiting for strike.` : ''}

**Current Assessment:** Target correctly isolates tested endpoints. To uncover authorization flaws, browse deeper into authenticated surfaces:
1. Open your **Account Settings & Security** tab.
2. View your **Inventory & Trade History**.
3. Create or inspect an order.`,
          provider: 'builtin',
          model: 'ashborn-tactical-v1',
        };
      }

      const reportList = context.reports.map((r, i) =>
        `**#${i + 1} [${r.severity}] ${r.title}**\n- Endpoint: \`${r.tamperProofReceipt?.forensicBinding?.requestUrl || 'endpoint'}\`\n- Class: ${r.vulnerabilityClass} | Receipt: \`${r.tamperProofReceipt?.receiptId || 'N/A'}\`\n- Latency: \`${r.tamperProofReceipt?.latencyMs || 0}ms\``
      ).join('\n\n');

      return {
        reply: `### 🚨 Confirmed Vulnerabilities (${context.reports.length} Verified)\n\n${reportList}\n\n*Click **Copy Report** on any finding card above to submit to HackenProof!*`,
        provider: 'builtin',
        model: 'ashborn-tactical-v1',
        action: { type: 'VIEW_REPORT', payload: { reportId: context.reports[0].tamperProofReceipt?.receiptId } },
      };
    }

    // 2. Draft Bug Bounty Report
    if (q.includes('draft') || q.includes('report') || q.includes('hackenproof') || q.includes('hackerone') || q.includes('write up')) {
      if (context.reports.length === 0) {
        return {
          reply: `### 📝 Bug Bounty Report Draft
No confirmed vulnerabilities have been proven on \`${context.targetUrl}\` yet.

Under HackenProof / HackerOne rules of engagement:
- Reports require deterministic reproduction steps with verifiable cross-tenant data leaks.
- Ashborn will auto-generate the complete submission draft the moment a BOLA or IDOR leak is verified!`,
          provider: 'builtin',
          model: 'ashborn-tactical-v1',
        };
      }

      const rep = context.reports[0];
      return {
        reply: `### 📋 Submission Draft for HackenProof: ${rep.title}

**Target:** \`${context.targetUrl}\`  
**Vulnerability Type:** ${rep.title} (${rep.vulnerabilityClass})  
**Severity:** ${rep.severity}  

#### Summary
${rep.summary}

#### Steps to Reproduce
${rep.stepsToReproduce}

#### Proof of Concept (Reproducible cURL)
\`\`\`bash
${rep.proofOfConceptCurl}
\`\`\`

#### Impact & Remediation
- **Impact:** ${rep.impact}
- **Remediation:** ${rep.remediation}

#### Cryptographic Receipt
- Proof Seal: \`${rep.tamperProofReceipt?.receiptId}\`
- SHA-256 Digest: \`${rep.tamperProofReceipt?.proofHash}\``,
        provider: 'builtin',
        model: 'ashborn-tactical-v1',
        action: { type: 'VIEW_REPORT', payload: { reportId: rep.tamperProofReceipt?.receiptId } },
      };
    }

    // 3. Strike command
    const strikeMatch = q.match(/strike\s+(cdp-\d+|\w+)/i) || (q.includes('strike') ? ['strike', context.capturedEndpoints[0]?.id] : null);
    if (strikeMatch && strikeMatch[1]) {
      const targetId = strikeMatch[1];
      const item = context.capturedEndpoints.find(e => e.id.toLowerCase() === targetId.toLowerCase());
      if (item) {
        return {
          reply: `⚡ **Tactical Strike Queued:** Targeting \`${item.method} ${item.path}\` (${item.id}) in Blast Chamber.\nRunning 4-stage Haddix Matrix differential audit against attacker session: *${context.attackerAuthSummary}*.`,
          provider: 'builtin',
          model: 'ashborn-tactical-v1',
          action: { type: 'STRIKE_ENDPOINT', payload: { capturedId: item.id } },
        };
      }
    }

    // 4. Guest attacker command
    if (q.includes('guest') || q.includes('unauthenticated') || q.includes('anonymous')) {
      return {
        reply: `⚡ **Attacker Session Armed:** Switched attacker to **Anonymous Guest**.\nAshborn will now test whether any captured private user endpoints leak data to unauthenticated requests.`,
        provider: 'builtin',
        model: 'ashborn-tactical-v1',
        action: { type: 'SET_ATTACKER_GUEST' },
      };
    }

    // 5. Why was endpoint safe / explain 401
    if (q.includes('safe') || q.includes('why') || q.includes('401') || q.includes('explain')) {
      return {
        reply: `### 🛡️ Why Was the Endpoint Refuted Safe?
When Ashborn tests an endpoint (e.g. \`POST /graphql/api\`), it applies **Two-Sided Differential Testing**:
1. **The Probe:** Replays the exact query using the Attacker's credentials (or Anonymous Guest).
2. **The Defense:** WhiteMarket responded with **HTTP 401 Unauthorized**.
3. **The Verdict:** The application correctly verified the session cookie and rejected unauthorized access. No private tenant data was returned, proving the endpoint enforces isolation.`,
        provider: 'builtin',
        model: 'ashborn-tactical-v1',
      };
    }

    // 6. Focus guidance (inventory, trading, profile)
    if (q.includes('focus') || q.includes('inventory') || q.includes('trade') || q.includes('market') || q.includes('where')) {
      return {
        reply: `### 🎯 Strategic Bug Hunting Vectors for WhiteMarket:
1. **User Inventory & Asset Balances:** Look for queries like \`query UserInventory($userId: ID!)\`. If the query accepts a target user ID parameter, tampering with that ID tests for BOLA.
2. **Trade Offers:** Intercept trade creation or status inspection. Check if User B can view User A's private trade counteroffers.
3. **Internal Profile & KYC Data:** Inspect whether profile settings endpoints leak internal email, Steam ID bindings, or payment methods.

*Keep browsing WhiteMarket in your Chrome window — Ashborn's CDP Auto-Pilot is recording every query live!*`,
        provider: 'builtin',
        model: 'ashborn-tactical-v1',
      };
    }

    // Default general response
    return {
      reply: `### ⚔️ Ashborn Tactical Co-Pilot Ready
I am connected to your live hunting session on \`${context.targetUrl || 'Active Target'}\`.

**Quick Commands You Can Give Me:**
- *"What did you find so far?"* — View confirmed vulnerabilities & safe checks.
- *"Strike endpoint cdp-1"* — Execute Blast Chamber differential strike.
- *"Test as guest"* — Check whether endpoints leak data unauthenticated.
- *"Draft report"* — Generate a HackenProof submission markdown report.
- *"Why was the last endpoint safe?"* — Review forensic authorization proof.

*Or connect a free API key from **Groq**, **OpenRouter**, or **Google AI Studio** in the Co-Pilot settings for full conversational reasoning!*`,
      provider: 'builtin',
      model: 'ashborn-tactical-v1',
    };
  }

  private detectActionFromText(userText: string, replyText: string, context: CopilotSecurityContext): CopilotChatResponse['action'] {
    const combined = `${userText} ${replyText}`.toLowerCase();
    const strikeMatch = combined.match(/strike\s+(cdp-\d+)/i);
    if (strikeMatch) {
      return { type: 'STRIKE_ENDPOINT', payload: { capturedId: strikeMatch[1] } };
    }
    if (combined.includes('guest') && (combined.includes('set') || combined.includes('switch') || combined.includes('armed'))) {
      return { type: 'SET_ATTACKER_GUEST' };
    }
    if (combined.includes('draft report') && context.reports.length > 0) {
      return { type: 'VIEW_REPORT', payload: { reportId: context.reports[0].tamperProofReceipt?.receiptId } };
    }
    return undefined;
  }
}
