/**
 * BaseGuard-402 Custom Action Plugin for ElizaOS / ai16z Autonomous Trading Agents
 * Plug into your character's plugins[] array to screen EVM calldata & Base tokens before signing.
 */

const BASEGUARD_URL = "https://baseguard-402.vercel.app";

export interface ElizaActionContext {
  calldata?: string;
  to?: string;
  tokenAddress?: string;
  paymentTx?: string;
  demo?: boolean;
}

export const baseGuardPreTradeAction = {
  name: "BASEGUARD_PRETRADE_FIREWALL",
  similes: ["AUDIT_CALLDATA", "CHECK_HONEYPOT", "VERIFY_BASE_SWAP", "SCREEN_TRANSACTION"],
  description:
    "Audits EVM calldata for unlimited approval drainers ($0.003 USDC) and simulates Base L2 token swap preflight ($0.005 USDC) via BaseGuard-402.",

  validate: async (_runtime: unknown, message: { content?: { text?: string } }): Promise<boolean> => {
    const text = message?.content?.text || "";
    return /0x[a-fA-F0-9]{8,}/.test(text);
  },

  handler: async (
    _runtime: unknown,
    _message: unknown,
    state: ElizaActionContext,
    _options: Record<string, unknown>,
    callback?: (response: { text: string; data?: unknown }) => void
  ): Promise<boolean> => {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (state.paymentTx) {
      headers["X-Payment-Tx"] = state.paymentTx;
    }

    const useDemo = !state.paymentTx && state.demo !== false;
    const qs = useDemo ? "?demo=true" : "";

    if (state.calldata) {
      const res = await fetch(`${BASEGUARD_URL}/api/v1/calldata-firewall${qs}`, {
        method: "POST",
        headers,
        body: JSON.stringify({ calldata: state.calldata, to: state.to })
      });
      const data = await res.json();
      const verdict = data.verdict?.action || `HTTP_${res.status}`;
      callback?.({
        text: `BaseGuard-402 Calldata Verdict: ${verdict} (Risk ${data.verdict?.riskScore ?? "N/A"}/100). ${data.recommendation || ""}`,
        data
      });
      return verdict !== "BLOCK";
    }

    if (state.tokenAddress) {
      const res = await fetch(`${BASEGUARD_URL}/api/v1/swap-preflight${qs}`, {
        method: "POST",
        headers,
        body: JSON.stringify({ tokenAddress: state.tokenAddress, tradeAmountUsd: 1000 })
      });
      const data = await res.json();
      const verdict = data.verdict?.action || `HTTP_${res.status}`;
      callback?.({
        text: `BaseGuard-402 Swap Preflight: ${verdict} (Honeypot Prob: ${data.verdict?.honeypotProbability ?? "N/A"}%).`,
        data
      });
      return verdict !== "BLOCK";
    }

    callback?.({ text: "Provide either `calldata` or `tokenAddress` for BaseGuard-402 screening." });
    return false;
  }
};

export const baseGuardElizaPlugin = {
  name: "baseguard-402",
  description: "Ultra-low-cost x402 pre-trade firewall and Base L2 swap simulator",
  actions: [baseGuardPreTradeAction]
};
