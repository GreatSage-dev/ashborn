import { spawn } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AshbornReceipt, DiscoveredEndpoint, DualSessionContext, FormattedReport, HttpMethod, TargetScope } from '../types.js';
import { CurlParser } from './curl_parser.js';
import { SafetyGovernor } from '../governor/safety_governor.js';
import { BlastChamber } from '../chamber/blast_chamber.js';
import { HaddixMatrix } from '../engine/haddix_matrix.js';
import { ReportGenerator } from '../reporter/markdown_receipt.js';
import { TargetLedger } from '../storage/target_ledger.js';

export interface CdpTargetInfo {
  id: string;
  title: string;
  url: string;
  type: string;
  webSocketDebuggerUrl?: string;
}

export interface CdpCookie {
  name: string;
  value: string;
  domain?: string;
}

export type CapturedAuditStatus =
  | 'CAPTURED'
  | 'TESTING'
  | 'CONFIRMED_VULNERABILITY'
  | 'REFUTED_SAFE'
  | 'BLOCKED_BY_GOVERNOR'
  | 'SKIPPED_NO_ATTACKER'
  | 'SKIPPED_UNAUTH'
  | 'SKIPPED_MUTATING';

export interface CapturedTrafficItem {
  id: string;
  capturedAt: string;
  url: string;
  baseUrl: string;
  path: string;
  host: string;
  method: HttpMethod;
  headers: Record<string, string>;
  body?: string;
  statusCode?: number;
  resourceType: string;
  extractedResourceId?: string;
  normalizedTemplate: string;
  isHighValue: boolean;
  authMode: string;
  curlCommand: string;
  auditStatus: CapturedAuditStatus;
  auditReason?: string;
}

export interface AutopilotConnectOptions {
  cdpHttpUrl?: string;
  targetId?: string;
  allowedHosts?: string[];
  programName?: string;
  readOnlySafeMode?: boolean;
}

export interface AutopilotOptions {
  ledgerBaseDir?: string;
  cadenceDelayMs?: { min: number; max: number };
  timeoutMs?: number;
}

export interface AutopilotStatusSnapshot {
  connected: boolean;
  cdpHttpUrl: string;
  targetTitle: string;
  targetUrl: string;
  allowedHosts: string[];
  programName: string;
  readOnlySafeMode: boolean;
  hasAttackerSession: boolean;
  attackerAuthSummary: string;
  queuePending: number;
  isProcessing: boolean;
  capturedEndpoints: CapturedTrafficItem[];
  receipts: AshbornReceipt[];
  reports: FormattedReport[];
  logs: string[];
  lastError?: string;
}

const IGNORED_REPLAY_HEADERS = new Set([
  'host',
  'content-length',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'accept-encoding',
  'content-encoding',
  'te',
  'trailer',
  'upgrade',
]);

const STATIC_EXT_REGEX = /\.(?:js|mjs|cjs|css|png|jpg|jpeg|gif|webp|svg|woff2?|ttf|eot|ico|map|mp4|webm|mp3|wav|pdf)(?:\?|$)/i;

const TELEMETRY_HOST_PATTERNS = [
  /google-analytics\.com/i,
  /googletagmanager\.com/i,
  /doubleclick\.net/i,
  /sentry\.io/i,
  /datadoghq\.com/i,
  /cloudflareinsights\.com/i,
  /clarity\.ms/i,
  /hotjar\.com/i,
  /intercom\.io/i,
  /segment\.(io|com)/i,
  /amplitude\.com/i,
  /mixpanel\.com/i,
  /recaptcha\.net/i,
  /hcaptcha\.com/i,
  /gstatic\.com/i,
  /fonts\.googleapis\.com/i,
];

const AUTOPILOT_EXTRA_BLOCKLIST: RegExp[] = [
  /\/logout\b/i,
  /\/sign[-_]?out\b/i,
  /\/log[-_]?out\b/i,
  /\/revoke\b/i,
  /\/auth\/disconnect/i,
];

interface PendingCdpRequest {
  requestId: string;
  url: string;
  method: string;
  resourceType: string;
  baseHeaders: Record<string, string>;
  extraHeaders: Record<string, string>;
  postData?: string;
  statusCode?: number;
  mimeType?: string;
  finalized?: boolean;
  timer?: ReturnType<typeof setTimeout>;
}

/**
 * CHROME DEVTOOLS PROTOCOL (CDP) SCOUT
 * Pure helpers for listing debuggable Chrome tabs, filtering API traffic,
 * merging HttpOnly ExtraInfo cookies, and normalizing endpoint templates.
 */
export class CdpScout {
  /**
   * Lists open page targets from Chrome's DevTools HTTP endpoint (default http://127.0.0.1:9222).
   */
  public static async listTargets(cdpHttpUrl = 'http://127.0.0.1:9222'): Promise<CdpTargetInfo[]> {
    const cleanBase = cdpHttpUrl.replace(/\/$/, '');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const res = await fetch(`${cleanBase}/json/list`, { signal: controller.signal });
      if (!res.ok) {
        throw new Error(`CDP HTTP ${res.status} from ${cleanBase}/json/list`);
      }
      const list = (await res.json()) as CdpTargetInfo[];
      return list.filter(
        t =>
          t.type === 'page' &&
          Boolean(t.webSocketDebuggerUrl) &&
          !/^(?:devtools|chrome|chrome-extension|edge):\/\//i.test(t.url)
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Determines whether a CDP network event represents in-scope API traffic rather than noise.
   */
  public static isApiTrafficCandidate(
    url: string,
    resourceType: string,
    mimeType = '',
    allowedHosts: string[] = []
  ): boolean {
    if (!/^https?:\/\//i.test(url)) return false;

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return false;
    }

    if (allowedHosts.length > 0 && !SafetyGovernor.isHostAllowed(url, allowedHosts)) {
      return false;
    }

    if (TELEMETRY_HOST_PATTERNS.some(rx => rx.test(parsed.hostname))) {
      return false;
    }

    if (STATIC_EXT_REGEX.test(parsed.pathname)) {
      return false;
    }

    const rType = resourceType.toLowerCase();
    const mType = mimeType.toLowerCase();
    if (rType === 'xhr' || rType === 'fetch') return true;
    if (mType.includes('json') || mType.includes('graphql')) return true;
    if (/\/(?:api|v\d+|graphql|internal|user|account|orders?|trades?|wallet|profile|inventory|settings|api_key)\b/i.test(parsed.pathname)) {
      return true;
    }
    return false;
  }

  /**
   * Merges requestWillBeSent headers, requestWillBeSentExtraInfo headers (which carry HttpOnly cookies),
   * and fallback Network.getCookies results, while stripping hop-by-hop headers.
   */
  public static mergeCdpHeaders(
    baseHeaders: Record<string, string>,
    extraHeaders: Record<string, string>,
    cdpCookies: CdpCookie[] = []
  ): Record<string, string> {
    const merged: Record<string, string> = {};

    const setCaseInsensitive = (key: string, val: string) => {
      const lower = key.toLowerCase();
      if (lower.startsWith(':') || IGNORED_REPLAY_HEADERS.has(lower)) return;
      for (const existing of Object.keys(merged)) {
        if (existing.toLowerCase() === lower) {
          delete merged[existing];
        }
      }
      const canonicalKey = lower === 'cookie' ? 'Cookie' : key;
      merged[canonicalKey] = val;
    };

    for (const [k, v] of Object.entries(baseHeaders || {})) {
      if (typeof v === 'string') setCaseInsensitive(k, v);
    }
    for (const [k, v] of Object.entries(extraHeaders || {})) {
      if (typeof v === 'string') setCaseInsensitive(k, v);
    }

    if (!merged['Cookie'] && cdpCookies.length > 0) {
      merged['Cookie'] = cdpCookies.map(c => `${c.name}=${c.value}`).join('; ');
    }

    return merged;
  }

  /**
   * Collapses per-record IDs into a canonical template key to prevent redundant probing.
   */
  public static normalizeEndpointTemplate(urlStr: string, method: HttpMethod): string {
    try {
      const parsed = new URL(urlStr);
      const normalizedPath = parsed.pathname
        .replace(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, '{uuid}')
        .replace(/\/(\d+)(?=\/|$)/g, '/{id}')
        .replace(/\/[a-zA-Z]{2,10}_[a-zA-Z0-9_\-]{2,}(?=\/|$)/g, '/{record_id}')
        .replace(/\/[0-9a-f]{24}(?=\/|$)/gi, '/{object_id}');
      return `${method}:${parsed.hostname.toLowerCase()}:${normalizedPath}`;
    } catch {
      return `${method}:${urlStr}`;
    }
  }

  /**
   * Derives default scope allowlist patterns (apex domain + subdomains) from a page URL.
   */
  public static deriveScopeHostsFromUrl(urlStr: string): string[] {
    try {
      const host = new URL(urlStr).hostname.toLowerCase();
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host === 'localhost') {
        return [host];
      }
      const parts = host.split('.').filter(Boolean);
      if (parts.length <= 2) {
        return [host, `*.${host}`];
      }
      const apex = parts.slice(-2).join('.');
      return [host, apex, `*.${apex}`];
    } catch {
      return [];
    }
  }

  /**
   * Synthesizes a reproducible cURL command from captured request metadata.
   */
  public static synthesizeCurl(
    url: string,
    method: HttpMethod,
    headers: Record<string, string>,
    body?: string
  ): string {
    const escapedUrl = url.replace(/'/g, "'\\''");
    const headerFlags = Object.entries(headers)
      .map(([k, v]) => `-H '${k}: ${v.replace(/'/g, "'\\''")}'`)
      .join(' ');
    const bodyFlag = body ? `--data-raw '${body.replace(/'/g, "'\\''")}'` : '';
    return `curl -X ${method} '${escapedUrl}' ${headerFlags} ${bodyFlag}`.trim();
  }

  public static describeAuthHeaders(headers: Record<string, string>): string {
    const lowerKeys = new Map<string, string>();
    for (const [k, v] of Object.entries(headers)) {
      lowerKeys.set(k.toLowerCase(), v);
    }
    if (lowerKeys.has('authorization')) return 'Authorization Header';
    const cookieVal = lowerKeys.get('cookie');
    if (cookieVal && cookieVal.trim().length > 0) {
      const hasCsrf = ['x-xsrf-token', 'x-csrf-token', 'csrf-token', 'xsrf-token', 'x-csrftoken'].some(k =>
        lowerKeys.has(k)
      );
      return hasCsrf ? 'Cookies + CSRF' : 'Cookies';
    }
    return 'Unauthenticated';
  }
}

/**
 * Finds and spawns Google Chrome or Microsoft Edge with remote debugging enabled
 * using an isolated profile directory so it works cleanly alongside existing browser windows.
 */
export async function launchDebugChrome(
  targetUrl = 'https://white.market',
  port = 9222
): Promise<{ launched: boolean; alreadyRunning: boolean; cdpHttpUrl: string; browserPath?: string; profileDir: string }> {
  const cdpHttpUrl = `http://127.0.0.1:${port}`;

  // Check if a debug Chrome instance is already listening on this port
  try {
    const checkRes = await fetch(`${cdpHttpUrl}/json/version`);
    if (checkRes.ok) {
      return { launched: false, alreadyRunning: true, cdpHttpUrl, profileDir: 'existing' };
    }
  } catch {}

  const candidates =
    process.platform === 'win32'
      ? [
          'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
          'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
          join(process.env.LOCALAPPDATA || '', 'Google\\Chrome\\Application\\chrome.exe'),
          'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
          'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
        ]
      : process.platform === 'darwin'
      ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']
      : ['google-chrome', 'chromium', 'chromium-browser'];

  const browserPath = candidates.find(p => !p.includes('\\') && !p.includes('/') ? true : existsSync(p));
  if (!browserPath) {
    throw new Error('Could not find Chrome or Edge executable. Start Chrome manually with --remote-debugging-port=9222.');
  }

  const baseProfileRoot = process.env.LOCALAPPDATA || tmpdir();
  const profileDir = join(baseProfileRoot, 'Ashborn', 'chrome-debug-profile');
  if (!existsSync(profileDir)) {
    mkdirSync(profileDir, { recursive: true });
  }

  const child = spawn(
    browserPath,
    [
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${profileDir}`,
      '--no-first-run',
      '--no-default-browser-check',
      targetUrl,
    ],
    { detached: true, stdio: 'ignore' }
  );
  child.unref();

  // Wait up to 4 seconds for the CDP HTTP endpoint to come alive
  const deadline = Date.now() + 4000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${cdpHttpUrl}/json/version`);
      if (res.ok) {
        return { launched: true, alreadyRunning: false, cdpHttpUrl, browserPath, profileDir };
      }
    } catch {}
    await new Promise(r => setTimeout(r, 200));
  }

  throw new Error('Browser started, but CDP debug port 9222 did not open in time.');
}

/**
 * LIVE AUTONOMOUS CDP AUTO-PILOT
 * Streams DevTools Network events over WebSocket, merges HttpOnly cookies,
 * and sequentially tests captured endpoints in the Blast Chamber under Safety Governor rules.
 */
export class CdpAutopilot {
  private ws: WebSocket | null = null;
  private cdpHttpUrl = 'http://127.0.0.1:9222';
  private targetInfo: CdpTargetInfo | null = null;
  private allowedHosts: string[] = [];
  private programName = 'autopilot_target';
  private readOnlySafeMode = true;

  private attackerSession: {
    headers: Record<string, string>;
    token: string;
    authSummary: string;
  } | null = null;

  private pendingRequests = new Map<string, PendingCdpRequest>();
  private capturedEndpoints: CapturedTrafficItem[] = [];
  private testedTemplates = new Set<string>();
  private templateOutcomes = new Map<string, { status: CapturedAuditStatus; reason: string }>();
  private receipts: AshbornReceipt[] = [];
  private reports: FormattedReport[] = [];
  private strikeQueue: CapturedTrafficItem[] = [];
  private isProcessing = false;
  private logs: string[] = [];
  private lastError?: string;

  private rpcIdCounter = 1;
  private pendingRpc = new Map<number, {
    resolve: (val: Record<string, unknown>) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();

  private readonly ledger: TargetLedger;
  private readonly cadenceDelayMs: { min: number; max: number };
  private readonly timeoutMs: number;
  private itemSeq = 0;

  constructor(options: AutopilotOptions = {}) {
    this.ledger = new TargetLedger(options.ledgerBaseDir || 'targets');
    this.cadenceDelayMs = options.cadenceDelayMs ?? { min: 450, max: 950 };
    this.timeoutMs = options.timeoutMs ?? 6000;
  }

  private log(msg: string): void {
    const stamp = new Date().toISOString().slice(11, 19);
    this.logs.unshift(`[${stamp}] ${msg}`);
    if (this.logs.length > 60) {
      this.logs.length = 60;
    }
  }

  public setAttackerFromCurl(attackerCurl: string): { hasAttackerSession: boolean; attackerAuthSummary: string } {
    const parsed = CurlParser.parse(attackerCurl);
    const authSummary = CdpScout.describeAuthHeaders(parsed.replayHeaders);
    if (authSummary === 'Unauthenticated') {
      throw new Error('No session cookie or Authorization token found in User B cURL.');
    }

    this.attackerSession = {
      headers: parsed.replayHeaders,
      token: parsed.bearerToken || 'cookie_session_b',
      authSummary,
    };
    this.log(`Attacker (User B) session locked: ${authSummary}`);

    // Re-queue previously skipped items that were waiting on Attacker session
    for (const item of this.capturedEndpoints) {
      if (item.auditStatus === 'SKIPPED_NO_ATTACKER') {
        item.auditStatus = 'CAPTURED';
        item.auditReason = undefined;
        this.strikeQueue.push(item);
      }
    }
    void this.processQueue();

    return { hasAttackerSession: true, attackerAuthSummary: authSummary };
  }

  /**
   * Captures Account B's cookies (including HttpOnly + XSRF-TOKEN) directly from a second CDP tab (e.g. Incognito).
   */
  public async captureAttackerFromTab(
    cdpHttpUrl: string,
    targetId: string
  ): Promise<{ hasAttackerSession: boolean; attackerAuthSummary: string }> {
    const targets = await CdpScout.listTargets(cdpHttpUrl);
    const target = targets.find(t => t.id === targetId);
    if (!target || !target.webSocketDebuggerUrl) {
      throw new Error(`CDP target ${targetId} not found.`);
    }

    const cookies = await this.fetchTabCookiesOneShot(target.webSocketDebuggerUrl, target.url);
    if (cookies.length === 0) {
      throw new Error('No cookies found in selected tab. Make sure Account B is logged in on that tab.');
    }

    const headers: Record<string, string> = {
      Cookie: cookies.map(c => `${c.name}=${c.value}`).join('; '),
    };
    const xsrfCookie = cookies.find(c => /^(?:xsrf-token|csrf-token|_csrf|csrftoken)$/i.test(c.name));
    if (xsrfCookie) {
      try {
        headers['X-XSRF-TOKEN'] = decodeURIComponent(xsrfCookie.value);
      } catch {
        headers['X-XSRF-TOKEN'] = xsrfCookie.value;
      }
    }

    const authSummary = `${CdpScout.describeAuthHeaders(headers)} (${cookies.length} from tab)`;
    this.attackerSession = {
      headers,
      token: 'cdp_tab_session_b',
      authSummary,
    };
    this.log(`Captured Attacker (User B) session from tab "${target.title}": ${authSummary}`);

    for (const item of this.capturedEndpoints) {
      if (item.auditStatus === 'SKIPPED_NO_ATTACKER') {
        item.auditStatus = 'CAPTURED';
        item.auditReason = undefined;
        this.strikeQueue.push(item);
      }
    }
    void this.processQueue();

    return { hasAttackerSession: true, attackerAuthSummary: authSummary };
  }

  private async fetchTabCookiesOneShot(wsUrl: string, pageUrl: string): Promise<CdpCookie[]> {
    return new Promise<CdpCookie[]>((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      const timer = setTimeout(() => {
        try { ws.close(); } catch {}
        reject(new Error('Timed out reading cookies from CDP tab.'));
      }, 3000);

      ws.addEventListener('open', () => {
        ws.send(JSON.stringify({ id: 1, method: 'Network.enable' }));
        ws.send(JSON.stringify({ id: 2, method: 'Network.getCookies', params: { urls: [pageUrl] } }));
      });

      ws.addEventListener('message', ev => {
        try {
          const msg = JSON.parse(String(ev.data)) as { id?: number; result?: { cookies?: CdpCookie[] } };
          if (msg.id === 2) {
            clearTimeout(timer);
            try { ws.close(); } catch {}
            resolve(msg.result?.cookies || []);
          }
        } catch {}
      });

      ws.addEventListener('error', () => {
        clearTimeout(timer);
        reject(new Error('WebSocket error while reading cookies from CDP tab.'));
      });
    });
  }

  public async connect(options: AutopilotConnectOptions = {}): Promise<AutopilotStatusSnapshot> {
    await this.disconnect();

    this.cdpHttpUrl = (options.cdpHttpUrl || 'http://127.0.0.1:9222').replace(/\/$/, '');
    this.readOnlySafeMode = options.readOnlySafeMode ?? true;
    this.lastError = undefined;

    const targets = await CdpScout.listTargets(this.cdpHttpUrl);
    if (targets.length === 0) {
      throw new Error(`No open browser tabs found on ${this.cdpHttpUrl}. Open your target site in the debug browser first.`);
    }

    const chosen = options.targetId ? targets.find(t => t.id === options.targetId) : targets[0];
    if (!chosen || !chosen.webSocketDebuggerUrl) {
      throw new Error('Selected Chrome tab does not expose a WebSocket debugger URL.');
    }

    this.targetInfo = chosen;
    this.allowedHosts =
      options.allowedHosts && options.allowedHosts.length > 0
        ? options.allowedHosts
        : CdpScout.deriveScopeHostsFromUrl(chosen.url);
    this.programName = options.programName || (this.allowedHosts[0] || 'autopilot_target');

    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(chosen.webSocketDebuggerUrl!);
      this.ws = ws;
      let settled = false;

      const connectTimeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(new Error('Timed out connecting to Chrome tab WebSocket.'));
        }
      }, 4000);

      ws.addEventListener('open', () => {
        clearTimeout(connectTimeout);
        if (!settled) {
          settled = true;
          resolve();
        }
      });

      ws.addEventListener('message', ev => {
        this.handleCdpMessage(String(ev.data));
      });

      ws.addEventListener('close', () => {
        if (this.ws === ws) {
          this.ws = null;
          this.log('Disconnected from Chrome DevTools.');
        }
      });

      ws.addEventListener('error', () => {
        this.lastError = 'Chrome DevTools WebSocket error.';
        if (!settled) {
          settled = true;
          clearTimeout(connectTimeout);
          reject(new Error(this.lastError));
        }
      });
    });

    await this.sendRpc('Network.enable');
    this.log(`Attached to "${chosen.title}" (${chosen.url}) | Scope: ${this.allowedHosts.join(', ')}`);
    return this.getStatus();
  }

  public async disconnect(): Promise<void> {
    for (const pending of this.pendingRequests.values()) {
      if (pending.timer) clearTimeout(pending.timer);
    }
    this.pendingRequests.clear();

    for (const rpc of this.pendingRpc.values()) {
      clearTimeout(rpc.timer);
      rpc.reject(new Error('CDP session closed.'));
    }
    this.pendingRpc.clear();

    if (this.ws) {
      const wsRef = this.ws;
      this.ws = null;
      try {
        wsRef.close();
      } catch {}
    }
    this.targetInfo = null;
  }

  public clearSessionResults(): void {
    this.capturedEndpoints = [];
    this.testedTemplates.clear();
    this.templateOutcomes.clear();
    this.receipts = [];
    this.reports = [];
    this.strikeQueue = [];
    this.logs = [];
    this.log('Cleared captured endpoints and findings for new run.');
  }

  public setReadOnlySafeMode(enabled: boolean): void {
    this.readOnlySafeMode = enabled;
    this.log(`Read-Only Safe Mode ${enabled ? 'ENABLED (GET only)' : 'DISABLED (Full Haddix Matrix)'}`);
  }

  public async strikeCapturedById(capturedId: string, allowMutations = true): Promise<CapturedTrafficItem> {
    const item = this.capturedEndpoints.find(c => c.id === capturedId);
    if (!item) {
      throw new Error(`Captured endpoint ${capturedId} not found.`);
    }
    await this.executeStrikeForItem(item, allowMutations, true);
    return item;
  }

  public getStatus(): AutopilotStatusSnapshot {
    return {
      connected: Boolean(this.ws && this.ws.readyState === WebSocket.OPEN),
      cdpHttpUrl: this.cdpHttpUrl,
      targetTitle: this.targetInfo?.title || '',
      targetUrl: this.targetInfo?.url || '',
      allowedHosts: [...this.allowedHosts],
      programName: this.programName,
      readOnlySafeMode: this.readOnlySafeMode,
      hasAttackerSession: Boolean(this.attackerSession),
      attackerAuthSummary: this.attackerSession?.authSummary || 'Not configured',
      queuePending: this.strikeQueue.length,
      isProcessing: this.isProcessing,
      capturedEndpoints: [...this.capturedEndpoints],
      receipts: [...this.receipts],
      reports: [...this.reports],
      logs: [...this.logs],
      lastError: this.lastError,
    };
  }

  private sendRpc(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error('Not connected to Chrome DevTools WebSocket.'));
    }
    const id = this.rpcIdCounter++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRpc.delete(id);
        reject(new Error(`CDP RPC timeout for ${method}`));
      }, 2500);
      this.pendingRpc.set(id, { resolve, reject, timer });
      this.ws!.send(JSON.stringify({ id, method, params }));
    });
  }

  private handleCdpMessage(raw: string): void {
    let msg: {
      id?: number;
      method?: string;
      params?: Record<string, unknown>;
      result?: Record<string, unknown>;
      error?: { message?: string };
    };
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (typeof msg.id === 'number' && this.pendingRpc.has(msg.id)) {
      const pending = this.pendingRpc.get(msg.id)!;
      this.pendingRpc.delete(msg.id);
      clearTimeout(pending.timer);
      if (msg.error) {
        pending.reject(new Error(msg.error.message || 'CDP RPC Error'));
      } else {
        pending.resolve(msg.result || {});
      }
      return;
    }

    if (!msg.method || !msg.params) return;

    if (msg.method === 'Network.requestWillBeSent') {
      const requestId = String(msg.params.requestId || '');
      const reqObj = (msg.params.request || {}) as {
        url?: string;
        method?: string;
        headers?: Record<string, string>;
        postData?: string;
      };
      const url = reqObj.url || '';
      const resourceType = String(msg.params.type || 'Other');

      if (!CdpScout.isApiTrafficCandidate(url, resourceType, '', this.allowedHosts)) {
        return;
      }

      const pending: PendingCdpRequest = {
        requestId,
        url,
        method: (reqObj.method || 'GET').toUpperCase(),
        resourceType,
        baseHeaders: reqObj.headers || {},
        extraHeaders: {},
        postData: reqObj.postData,
      };
      this.pendingRequests.set(requestId, pending);
    } else if (msg.method === 'Network.requestWillBeSentExtraInfo') {
      const requestId = String(msg.params.requestId || '');
      const pending = this.pendingRequests.get(requestId);
      if (pending) {
        const extraHeaders = (msg.params.headers || {}) as Record<string, string>;
        pending.extraHeaders = { ...pending.extraHeaders, ...extraHeaders };
      }
    } else if (msg.method === 'Network.responseReceived') {
      const requestId = String(msg.params.requestId || '');
      const pending = this.pendingRequests.get(requestId);
      if (!pending) return;

      const resp = (msg.params.response || {}) as { status?: number; mimeType?: string; url?: string };
      pending.statusCode = resp.status;
      pending.mimeType = resp.mimeType || '';
      if (msg.params.type) {
        pending.resourceType = String(msg.params.type);
      }

      if (!CdpScout.isApiTrafficCandidate(pending.url, pending.resourceType, pending.mimeType, this.allowedHosts)) {
        this.pendingRequests.delete(requestId);
        return;
      }

      // Defer slightly in case requestWillBeSentExtraInfo arrives out of order
      if (pending.timer) clearTimeout(pending.timer);
      pending.timer = setTimeout(() => {
        void this.finalizeCapturedRequest(requestId);
      }, 20);
    } else if (msg.method === 'Network.loadingFailed') {
      const requestId = String(msg.params.requestId || '');
      const pending = this.pendingRequests.get(requestId);
      if (pending?.timer) clearTimeout(pending.timer);
      this.pendingRequests.delete(requestId);
    }
  }

  private async finalizeCapturedRequest(requestId: string): Promise<void> {
    const pending = this.pendingRequests.get(requestId);
    if (!pending || pending.finalized) return;
    pending.finalized = true;
    if (pending.timer) clearTimeout(pending.timer);
    this.pendingRequests.delete(requestId);

    const methodUpper = pending.method as HttpMethod;
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(methodUpper)) {
      return;
    }

    let cookiesFromRpc: CdpCookie[] = [];
    const hasCookieHeader =
      Object.keys(pending.extraHeaders).some(k => k.toLowerCase() === 'cookie') ||
      Object.keys(pending.baseHeaders).some(k => k.toLowerCase() === 'cookie');

    if (!hasCookieHeader && this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        const res = await this.sendRpc('Network.getCookies', { urls: [pending.url] });
        if (Array.isArray(res.cookies)) {
          cookiesFromRpc = res.cookies as CdpCookie[];
        }
      } catch {}
    }

    const mergedHeaders = CdpScout.mergeCdpHeaders(pending.baseHeaders, pending.extraHeaders, cookiesFromRpc);
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(pending.url);
    } catch {
      return;
    }

    const extractedResourceId = CurlParser.extractResourceId(parsedUrl, pending.postData);
    const normalizedTemplate = CdpScout.normalizeEndpointTemplate(pending.url, methodUpper);
    const authMode = CdpScout.describeAuthHeaders(mergedHeaders);
    const path = parsedUrl.pathname + parsedUrl.search;
    const isHighValue =
      Boolean(extractedResourceId) ||
      /(user|account|org|order|invoice|trade|wallet|inventory|profile|api_key|session|address|withdraw)/i.test(path);

    const item: CapturedTrafficItem = {
      id: `cdp-${++this.itemSeq}`,
      capturedAt: new Date().toISOString(),
      url: pending.url,
      baseUrl: `${parsedUrl.protocol}//${parsedUrl.host}`,
      path,
      host: parsedUrl.hostname,
      method: methodUpper,
      headers: mergedHeaders,
      body: pending.postData,
      statusCode: pending.statusCode,
      resourceType: pending.resourceType,
      extractedResourceId,
      normalizedTemplate,
      isHighValue,
      authMode,
      curlCommand: CdpScout.synthesizeCurl(pending.url, methodUpper, mergedHeaders, pending.postData),
      auditStatus: 'CAPTURED',
    };

    this.capturedEndpoints.unshift(item);
    if (this.capturedEndpoints.length > 200) {
      this.capturedEndpoints.length = 200;
    }

    // Persist discovered endpoint to TargetLedger
    this.ledger.saveEndpoints(this.programName, [
      {
        path,
        method: methodUpper,
        parameters: extractedResourceId ? ['id'] : [],
        isStateMutating: methodUpper !== 'GET',
        sourceBundle: 'cdp_autopilot',
        sampleBody: pending.postData,
      },
    ]);

    this.log(`Captured ${methodUpper} ${path} [${pending.statusCode ?? '?'}] (${authMode})`);
    this.strikeQueue.push(item);
    void this.processQueue();
  }

  private async processQueue(): Promise<void> {
    if (this.isProcessing) return;
    this.isProcessing = true;

    try {
      while (this.strikeQueue.length > 0) {
        const item = this.strikeQueue.shift()!;
        await this.executeStrikeForItem(item, !this.readOnlySafeMode);
      }
    } finally {
      this.isProcessing = false;
    }
  }

  private async executeStrikeForItem(
    item: CapturedTrafficItem,
    allowMutations: boolean,
    force = false
  ): Promise<void> {
    // 1. Safety Governor & Logout Guard
    const safety = SafetyGovernor.isBlocked(item.url, item.method, AUTOPILOT_EXTRA_BLOCKLIST, this.allowedHosts);
    if (safety.blocked) {
      item.auditStatus = 'BLOCKED_BY_GOVERNOR';
      item.auditReason = safety.reason;
      this.log(`Governor blocked ${item.method} ${item.path}: ${safety.reason}`);
      return;
    }

    // 2. Skip unauthenticated traffic
    if (item.authMode === 'Unauthenticated') {
      item.auditStatus = 'SKIPPED_UNAUTH';
      item.auditReason = 'No session cookies or Authorization header present.';
      return;
    }

    // 3. Read-Only Safe Mode guard for passive browsing
    if (!allowMutations && item.method !== 'GET') {
      item.auditStatus = 'SKIPPED_MUTATING';
      item.auditReason = 'Paused in Read-Only Safe Mode. Click Strike to test manually.';
      return;
    }

    // 4. Require User B Attacker session
    if (!this.attackerSession) {
      item.auditStatus = 'SKIPPED_NO_ATTACKER';
      item.auditReason = 'Waiting for Account B session.';
      return;
    }

    // 4b. Identical session guard: prevent User A testing against User A
    const victimCookie = item.headers['Cookie'] || item.headers['cookie'] || '';
    const attackerCookie = this.attackerSession.headers['Cookie'] || this.attackerSession.headers['cookie'] || '';
    const victimAuth = item.headers['Authorization'] || item.headers['authorization'] || '';
    const attackerAuth = this.attackerSession.headers['Authorization'] || this.attackerSession.headers['authorization'] || '';
    if (
      (victimCookie && attackerCookie && victimCookie === attackerCookie && victimAuth === attackerAuth) ||
      (!victimCookie && !attackerCookie && victimAuth && attackerAuth && victimAuth === attackerAuth)
    ) {
      item.auditStatus = 'SKIPPED_NO_ATTACKER';
      item.auditReason = 'User A and User B have identical session credentials. Log into Account B in an Incognito tab.';
      this.log(`Skipped ${item.path}: identical session credentials between User A and User B.`);
      return;
    }

    // 5. Deduplicate by normalized template unless explicitly forced
    if (!force && this.testedTemplates.has(item.normalizedTemplate)) {
      const prev = this.templateOutcomes.get(item.normalizedTemplate);
      item.auditStatus = prev?.status || 'REFUTED_SAFE';
      item.auditReason = `Normalized template already audited (${prev?.reason || 'deduplicated'}).`;
      return;
    }

    item.auditStatus = 'TESTING';
    this.testedTemplates.add(item.normalizedTemplate);

    const scope: TargetScope = {
      name: this.programName,
      baseUrl: item.baseUrl,
      allowedHosts: this.allowedHosts,
      rulesOfEngagement: 'Authorized Chrome DevTools Auto-Pilot Audit',
    };

    const context: DualSessionContext = {
      victimToken: 'cdp_victim_session',
      victimResourceId: item.extractedResourceId || '1',
      attackerToken: this.attackerSession.token,
      victimHeaders: item.headers,
      attackerHeaders: this.attackerSession.headers,
    };

    const endpoint: DiscoveredEndpoint = {
      path: item.path,
      method: item.method,
      parameters: item.extractedResourceId ? ['id'] : [],
      isStateMutating: item.method !== 'GET',
      sourceBundle: 'curl_ingress',
      sampleBody: item.body,
    };

    const matrixStages = HaddixMatrix.generateMatrix(endpoint, item.baseUrl, context, scope);
    const publicGuardStage = matrixStages.find(s => s.stageName.includes('Public Resource Guard'));
    const attackStages = allowMutations
      ? matrixStages.filter(s => !s.stageName.includes('Public Resource Guard'))
      : matrixStages.filter(s => s.stageName.includes('Cross-Tenant IDOR'));

    const chamber = new BlastChamber({
      timeoutMs: this.timeoutMs,
      cadenceDelayMs: this.cadenceDelayMs,
      allowedHosts: this.allowedHosts,
    });

    // Stage 2: Public Resource Guard first
    let isPublicResource = false;
    if (publicGuardStage) {
      const guardRes = await chamber.executeCandidate(publicGuardStage.candidate);
      if (guardRes.result.passed) {
        isPublicResource = true;
      }
    }

    if (isPublicResource) {
      item.auditStatus = 'REFUTED_SAFE';
      item.auditReason = 'Public Resource Guard: unauthenticated request returned identical response.';
      this.templateOutcomes.set(item.normalizedTemplate, { status: item.auditStatus, reason: item.auditReason });
      this.log(`Refuted (Public): ${item.method} ${item.path}`);
      return;
    }

    let confirmed = false;
    let lastVerdictReason = 'Endpoint enforced cross-tenant isolation.';

    for (const stage of attackStages) {
      const stageSafety = SafetyGovernor.isBlocked(
        stage.candidate.targetUrl,
        stage.candidate.method,
        AUTOPILOT_EXTRA_BLOCKLIST,
        this.allowedHosts
      );
      if (stageSafety.blocked) {
        continue;
      }

      const { result, receipt } = await chamber.executeCandidate(stage.candidate);
      lastVerdictReason = result.reason;
      if (result.passed && receipt) {
        confirmed = true;
        this.ledger.recordReceipt(this.programName, receipt);
        if (!this.receipts.some(r => r.findingHash === receipt.findingHash)) {
          this.receipts.push(receipt);
          this.reports.push(ReportGenerator.generateHackerOneReport(receipt));
        }
        this.log(`CONFIRMED ${receipt.vector} on ${item.method} ${item.path} [${receipt.statusCode}]!`);
        break;
      }
    }

    if (confirmed) {
      item.auditStatus = 'CONFIRMED_VULNERABILITY';
      item.auditReason = 'Cross-tenant data leak confirmed in Blast Chamber.';
    } else {
      item.auditStatus = 'REFUTED_SAFE';
      item.auditReason = lastVerdictReason;
      this.log(`Refuted Safe: ${item.method} ${item.path}`);
    }

    this.templateOutcomes.set(item.normalizedTemplate, {
      status: item.auditStatus,
      reason: item.auditReason,
    });
  }
}
