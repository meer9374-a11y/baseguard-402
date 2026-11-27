export const PAY_TO = "0x6137ED1A93c8CFF1a6C3112A14bE04883f58E5F7";
export const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const WETH_BASE = "0x4200000000000000000000000000000000000006";
export const NETWORK = "base";
export const CHAIN_ID = 8453;

export const BASE_RPCS = [
  "https://mainnet.base.org",
  "https://base.llamarpc.com"
];

export const ANTI_REPLAY_WINDOW_SECONDS = 600;

export const PRICING = {
  "calldata-firewall": {
    endpoint: "/api/v1/calldata-firewall",
    amount: "3000",
    usdc: "0.003",
    description: "Deterministic EVM calldata & ABI selector phishing firewall (zero external API limits)"
  },
  "swap-preflight": {
    endpoint: "/api/v1/swap-preflight",
    amount: "5000",
    usdc: "0.005",
    description: "Direct Base RPC swap preflight simulation, pool liquidity depth & honeypot bytecode scan"
  },
  "token-intel": {
    endpoint: "/api/v1/token-intel",
    amount: "5000",
    usdc: "0.005",
    description: "Edge-cached DexScreener + GoPlus Base token liquidity & security aggregator"
  }
};

export const SERVER_START_TIME = Date.now();

export function setCorsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Payment-Tx, X-Payment, Authorization");
}

export function setDemoCacheHeaders(res) {
  res.setHeader("Cache-Control", "public, s-maxage=60, stale-while-revalidate=120");
  res.setHeader("X-BaseGuard-Cache", "demo-edge-60s");
}

export function setPaidEdgeCacheHeaders(res) {
  res.setHeader("Cache-Control", "public, s-maxage=15, stale-while-revalidate=30");
  res.setHeader("X-BaseGuard-Cache", "paid-edge-15s");
}

export function setNoCacheHeaders(res) {
  res.setHeader("Cache-Control", "no-store");
}

export function getPaymentTxHeader(req) {
  const headers = req.headers || {};
  return (
    headers["x-payment-tx"] ||
    headers["X-Payment-Tx"] ||
    headers["x-payment"] ||
    headers["X-Payment"] ||
    ""
  ).toString().trim();
}

export function isDemoRequest(req) {
  const query = req.query || {};
  if (query.demo === "true" || query.demo === "1") return true;
  try {
    const url = new URL(req.url || "/", "https://localhost");
    return url.searchParams.get("demo") === "true" || url.searchParams.get("demo") === "1";
  } catch {
    return false;
  }
}

export async function parseRequestBody(req) {
  if (req.body && typeof req.body === "object") {
    return req.body;
  }
  if (typeof req.body === "string" && req.body.trim()) {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }
  if (req.method === "GET" || req.method === "HEAD") {
    return {};
  }
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 256 * 1024) {
        resolve({});
      }
    });
    req.on("end", () => {
      if (!data.trim()) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

export function getRequestOrigin(req) {
  const proto = req.headers?.["x-forwarded-proto"] || "https";
  const host = req.headers?.["x-forwarded-host"] || req.headers?.host || "https://baseguard-402.vercel.app";
  if (host.startsWith("http://") || host.startsWith("https://")) return host;
  return `${proto}://${host}`;
}
