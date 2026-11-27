import {
  PAY_TO,
  USDC_BASE,
  NETWORK,
  CHAIN_ID,
  PRICING,
  SERVER_START_TIME,
  setCorsHeaders
} from "../../lib/config.js";
import { ethBlockNumber } from "../../lib/rpc.js";

export default async function handler(req, res) {
  setCorsHeaders(res);
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  res.setHeader("Cache-Control", "public, s-maxage=15, stale-while-revalidate=30");

  let rpcStatus = { ok: false, rpcUrl: null, blockNumber: null, latencyMs: null, error: null };
  try {
    const info = await ethBlockNumber();
    rpcStatus = {
      ok: true,
      rpcUrl: info.rpcUrl,
      blockNumber: info.blockNumber,
      latencyMs: info.latencyMs
    };
  } catch (err) {
    rpcStatus = { ok: false, error: err.message };
  }

  return res.status(200).json({
    service: "BaseGuard-402",
    version: "1.0.0",
    status: rpcStatus.ok ? "healthy" : "degraded",
    uptimeSeconds: Math.floor((Date.now() - SERVER_START_TIME) / 1000),
    network: {
      name: NETWORK,
      chainId: CHAIN_ID,
      usdcAsset: USDC_BASE,
      payTo: PAY_TO,
      rpc: rpcStatus
    },
    pricing: PRICING,
    quotaOptimization: {
      platform: "Vercel Hobby Tier Protected",
      dependencies: 0,
      demoCacheControl: "public, s-maxage=60, stale-while-revalidate=120",
      paidTokenIntelCacheControl: "public, s-maxage=15, stale-while-revalidate=30",
      antiReplayMode: "Stateless Base block timestamp window (600s)",
      calldataFirewallExternalCalls: 0
    },
    discovery: {
      mcp: "/mcp",
      x402Manifest: "/.well-known/x402.json",
      mcpManifest: "/.well-known/mcp.json",
      llmsTxt: "/llms.txt",
      openApi: "/openapi.json"
    }
  });
}
