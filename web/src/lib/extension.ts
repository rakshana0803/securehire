// Messaging bridge to the SecureHire Assessment Monitor Chrome extension (externally_connectable).
// The extension ID is fixed by the "key" in extension/manifest.json; override with VITE_EXTENSION_ID if needed.
export const EXTENSION_ID: string = (import.meta as any).env?.VITE_EXTENSION_ID || 'mlfnbgkkkndpcbmleppgablahalkeedn';

function chromeRuntime(): any {
  return (window as any).chrome?.runtime;
}

export function sendToExtension<T = any>(message: any, timeoutMs = 1500): Promise<T | null> {
  const rt = chromeRuntime();
  if (!rt?.sendMessage) return Promise.resolve(null);
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    try {
      rt.sendMessage(EXTENSION_ID, message, (resp: T) => {
        clearTimeout(timer);
        // reading lastError suppresses "Could not establish connection" console noise
        if (rt.lastError) return resolve(null);
        resolve(resp ?? null);
      });
    } catch { clearTimeout(timer); resolve(null); }
  });
}

export type AgentState = {
  status: 'not_used' | 'connecting' | 'monitoring' | 'idle' | 'ended' | 'not_running' | 'error';
  message?: string; monitors?: Record<string, string>; connection?: string | null; reviewItems?: number; alerts?: { at: string; text: string }[];
};
export const pingExtension = () => sendToExtension<{ ok: boolean; version: string; active?: boolean }>({ type: 'PING' });
/** agentToken is optional: when present the extension relays it to the local SecureHire desktop agent (Windows). */
export const startExtensionSession = (p: { sessionId: string; candidateId: number; sessionToken: string; apiBaseUrl: string; agentToken?: string }) =>
  sendToExtension<{ ok: boolean; error?: string }>({ type: 'START_SESSION', consentGiven: true, ...p }, 3000);
export const extensionStatus = () => sendToExtension<{ active: boolean; sessionId?: string; counts?: Record<string, number>; backend?: string; agent?: AgentState }>({ type: 'GET_STATUS' });
/** Is the desktop agent running on this computer? (asked via the extension; the page itself cannot reach localhost services) */
export const desktopAgentHealth = () => sendToExtension<{ ok: boolean; reachable: boolean; version?: string; active?: boolean }>({ type: 'AGENT_HEALTH' }, 2500);
export const endExtensionSession = () => sendToExtension({ type: 'END_SESSION' }, 3000);
