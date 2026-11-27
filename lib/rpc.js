import { BASE_RPCS } from "./config.js";

const DEFAULT_TIMEOUT_MS = 7000;

export async function rpcCall(method, params = [], timeoutMs = DEFAULT_TIMEOUT_MS) {
  let lastError = null;

  for (const rpcUrl of BASE_RPCS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const started = Date.now();
    try {
      const response = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method,
          params
        }),
        signal: controller.signal
      });
      clearTimeout(timer);

      if (!response.ok) {
        lastError = new Error(`RPC HTTP ${response.status} from ${rpcUrl}`);
        continue;
      }

      const payload = await response.json();
      if (payload.error) {
        lastError = new Error(`RPC error (${payload.error.code}): ${payload.error.message}`);
        continue;
      }

      return {
        result: payload.result,
        rpcUrl,
        latencyMs: Date.now() - started
      };
    } catch (err) {
      clearTimeout(timer);
      lastError = err;
    }
  }

  throw lastError || new Error("All Base Mainnet RPC endpoints failed");
}

export async function ethCall(to, data) {
  const { result, rpcUrl, latencyMs } = await rpcCall("eth_call", [
    { to, data },
    "latest"
  ]);
  return { result, rpcUrl, latencyMs };
}

export async function ethGetCode(address) {
  const { result, rpcUrl, latencyMs } = await rpcCall("eth_getCode", [
    address,
    "latest"
  ]);
  return { code: result || "0x", rpcUrl, latencyMs };
}

export async function ethGetTransactionReceipt(txHash) {
  const { result, rpcUrl, latencyMs } = await rpcCall("eth_getTransactionReceipt", [txHash]);
  return { receipt: result, rpcUrl, latencyMs };
}

export async function ethGetBlockByNumber(blockTag) {
  const { result, rpcUrl, latencyMs } = await rpcCall("eth_getBlockByNumber", [blockTag, false]);
  return { block: result, rpcUrl, latencyMs };
}

export async function ethBlockNumber() {
  const { result, rpcUrl, latencyMs } = await rpcCall("eth_blockNumber", []);
  return { blockNumber: parseInt(result, 16), hex: result, rpcUrl, latencyMs };
}
