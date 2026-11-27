/**
 * BaseGuard-402 x402 Pre-Trade Firewall Hook for Coinbase AgentKit (Base L2)
 * Drop this guard before any AgentKit wallet.sendTransaction() or swap execution.
 * Cost: $0.003 USDC (calldata firewall) / $0.005 USDC (swap preflight) ??Zero API keys.
 */

const BASEGUARD_URL = "https://baseguard-402.vercel.app";
const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

export interface AgentKitWallet {
  sendUsdcTransfer: (to: string, amountBaseUnits: string, asset: string) => Promise<string>;
}

export interface GuardVerdict {
  action: "ALLOW" | "WARN" | "BLOCK";
  severity?: string;
  riskScore?: number;
  honeypotProbability?: number;
}

/**
 * Pays x402 challenge automatically via AgentKit wallet and returns BaseGuard-402 audit result.
 */
async function callBaseGuardWithX402<T>(
  endpoint: string,
  payload: Record<string, unknown>,
  wallet?: AgentKitWallet,
  demoMode = false
): Promise<T> {
  const url = `${BASEGUARD_URL}${endpoint}${demoMode ? "?demo=true" : ""}`;

  // Step 1: Initial request (returns 200 in demo mode or 402 Payment Required in prod)
  const firstRes = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (firstRes.ok) {
    return (await firstRes.json()) as T;
  }

  if (firstRes.status !== 402 || !wallet) {
    throw new Error(`BaseGuard-402 returned HTTP ${firstRes.status}: ${await firstRes.text()}`);
  }

  // Step 2: Parse x402 payment requirement & stream micro-USDC on Base
  const challenge = await firstRes.json();
  const txHash = await wallet.sendUsdcTransfer(challenge.payTo, challenge.amount, challenge.asset || BASE_USDC);

  // Step 3: Retry with X-Payment-Tx proof (stateless on-chain verification)
  const paidRes = await fetch(`${BASEGUARD_URL}${endpoint}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Payment-Tx": txHash
    },
    body: JSON.stringify(payload)
  });

  if (!paidRes.ok) {
    throw new Error(`BaseGuard-402 paid verification failed (${paidRes.status}): ${await paidRes.text()}`);
  }

  return (await paidRes.json()) as T;
}

/**
 * Pre-swap safety hook for Coinbase AgentKit bots.
 * Throws if calldata is a drainer/unlimited approval or token fails Base RPC preflight.
 */
export async function assertSafeBaseTrade(params: {
  calldata: string;
  to: string;
  tokenAddress?: string;
  tradeAmountUsd?: number;
  wallet?: AgentKitWallet;
  demoMode?: boolean;
}): Promise<void> {
  const calldataAudit = await callBaseGuardWithX402<{ verdict: GuardVerdict; recommendation: string }>(
    "/api/v1/calldata-firewall",
    { calldata: params.calldata, to: params.to },
    params.wallet,
    params.demoMode
  );

  if (calldataAudit.verdict.action === "BLOCK") {
    throw new Error(
      `[BaseGuard-402 BLOCKED] Calldata risk ${calldataAudit.verdict.riskScore}/100: ${calldataAudit.recommendation}`
    );
  }

  if (params.tokenAddress) {
    const preflight = await callBaseGuardWithX402<{ verdict: GuardVerdict }>(
      "/api/v1/swap-preflight",
      { tokenAddress: params.tokenAddress, tradeAmountUsd: params.tradeAmountUsd ?? 1000 },
      params.wallet,
      params.demoMode
    );

    if (preflight.verdict.action === "BLOCK") {
      throw new Error(
        `[BaseGuard-402 BLOCKED] Honeypot probability ${preflight.verdict.honeypotProbability}% for ${params.tokenAddress}`
      );
    }
  }
}
