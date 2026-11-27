import { WETH_BASE, USDC_BASE } from "./config.js";
import { ethCall, ethGetCode } from "./rpc.js";

const UNISWAP_V3_FACTORY_BASE = "0x33128a8fC17869897dcE68Ed026d694621f6FDfD";

const BYTECODE_RISK_SIGNATURES = [
  { id: "BLACKLIST_FN", selector: "44337ea1", label: "blacklist(address)", score: 25 },
  { id: "IS_BLACKLISTED_FN", selector: "fe575a87", label: "isBlacklisted(address)", score: 15 },
  { id: "SET_TAX_OR_FEE", selector: "69fe0e2d", label: "setFee(uint256)", score: 20 },
  { id: "SET_MAX_TX", selector: "ec28438a", label: "setMaxTxAmount(uint256)", score: 15 },
  { id: "PAUSE_FN", selector: "8456cb59", label: "pause()", score: 15 },
  { id: "MINT_FN", selector: "40c10f19", label: "mint(address,uint256)", score: 15 },
  { id: "SELFDESTRUCT_OPCODE", selector: "ff", label: "potential-selfdestruct", score: 0 }
];

function isValidAddress(addr) {
  return typeof addr === "string" && /^0x[0-9a-fA-F]{40}$/.test(addr);
}

function padAddress(addr) {
  return addr.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

function padUint24(num) {
  return num.toString(16).padStart(64, "0");
}

function decodeUint256(hex) {
  if (!hex || hex === "0x") return null;
  try {
    return BigInt(hex.slice(0, 66));
  } catch {
    return null;
  }
}

function decodeAddress(hex) {
  if (!hex || hex.length < 66) return null;
  const addr = "0x" + hex.slice(26, 66);
  return addr === "0x0000000000000000000000000000000000000000" ? null : addr;
}

function decodeString(hex) {
  if (!hex || hex === "0x" || hex.length < 130) return null;
  try {
    const lenHex = hex.slice(66, 130);
    const len = parseInt(lenHex, 16);
    if (!Number.isFinite(len) || len <= 0 || len > 64) return null;
    const strHex = hex.slice(130, 130 + len * 2);
    const bytes = [];
    for (let i = 0; i < strHex.length; i += 2) {
      bytes.push(parseInt(strHex.slice(i, i + 2), 16));
    }
    return new TextDecoder().decode(new Uint8Array(bytes)).replace(/\0/g, "").trim();
  } catch {
    return null;
  }
}

async function safeEthCall(to, data) {
  try {
    const { result } = await ethCall(to, data);
    return result;
  } catch {
    return null;
  }
}

async function discoverUniswapV3Pool(tokenAddress) {
  const quoteTokens = [
    { symbol: "WETH", address: WETH_BASE, decimals: 18 },
    { symbol: "USDC", address: USDC_BASE, decimals: 6 }
  ];
  const feeTiers = [3000, 10000, 500];

  for (const quote of quoteTokens) {
    if (quote.address.toLowerCase() === tokenAddress.toLowerCase()) continue;
    for (const fee of feeTiers) {
      const data = "0x1698ee82" + padAddress(tokenAddress) + padAddress(quote.address) + padUint24(fee);
      const res = await safeEthCall(UNISWAP_V3_FACTORY_BASE, data);
      const pool = decodeAddress(res);
      if (pool) {
        return { poolAddress: pool, dex: "Uniswap V3 (Base)", feeTierBps: fee / 100, quote };
      }
    }
  }
  return null;
}

export async function simulateBaseSwapPreflight({
  tokenAddress,
  poolAddress = null,
  tradeAmountUsd = 1000
}) {
  if (!isValidAddress(tokenAddress)) {
    return {
      valid: false,
      error: "Invalid tokenAddress. Expected 42-character 0x-prefixed Base contract address."
    };
  }

  const started = Date.now();
  const codeResult = await ethGetCode(tokenAddress);
  const bytecode = (codeResult.code || "0x").toLowerCase();

  if (bytecode === "0x" || bytecode.length <= 2) {
    return {
      valid: true,
      engine: "BaseGuard-402 Direct Base RPC Swap Preflight v1.0",
      rpcUrl: codeResult.rpcUrl,
      latencyMs: Date.now() - started,
      tokenAddress,
      verdict: {
        action: "BLOCK",
        honeypotProbability: 100,
        estimatedPriceImpactPct: 100,
        reason: "Target address has no deployed EVM bytecode (EOA or self-destructed contract)."
      },
      contract: { isContract: false, bytecodeBytes: 0 }
    };
  }

  const [symbolHex, decimalsHex, totalSupplyHex, ownerHex, pausedHex] = await Promise.all([
    safeEthCall(tokenAddress, "0x95d89b41"),
    safeEthCall(tokenAddress, "0x313ce567"),
    safeEthCall(tokenAddress, "0x18160ddd"),
    safeEthCall(tokenAddress, "0x8da5cb5b"),
    safeEthCall(tokenAddress, "0x5c975abb")
  ]);

  const symbol = decodeString(symbolHex) || "UNKNOWN";
  const decimalsNum = decimalsHex ? Number(decodeUint256(decimalsHex) ?? 18n) : 18;
  const totalSupplyRaw = decodeUint256(totalSupplyHex);
  const owner = decodeAddress(ownerHex);
  const isPaused = pausedHex ? (decodeUint256(pausedHex) || 0n) === 1n : false;

  const bytecodeFlags = [];
  let trapScore = 5;

  for (const sig of BYTECODE_RISK_SIGNATURES) {
    if (sig.selector.length === 8 && bytecode.includes(sig.selector)) {
      bytecodeFlags.push({ id: sig.id, selector: `0x${sig.selector}`, label: sig.label });
      trapScore += sig.score;
    }
  }

  const isProxyPattern = bytecode.includes("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");
  if (isProxyPattern) {
    bytecodeFlags.push({ id: "UPGRADEABLE_PROXY", selector: "EIP-1967", label: "Upgradeable Proxy Storage Slot" });
    trapScore += 15;
  }

  if (isPaused) {
    trapScore += 70;
    bytecodeFlags.push({ id: "CONTRACT_PAUSED", selector: "0x5c975abb", label: "paused() === true (transfers halted)" });
  }

  if (owner) {
    trapScore += 10;
  }

  let poolInfo = null;
  if (poolAddress && isValidAddress(poolAddress)) {
    poolInfo = { poolAddress, dex: "User-Specified Pool (Base)", feeTierBps: null, quote: { symbol: "WETH", address: WETH_BASE, decimals: 18 } };
  } else {
    poolInfo = await discoverUniswapV3Pool(tokenAddress);
  }

  let poolMetrics = {
    found: false,
    poolAddress: poolAddress || null,
    dex: null,
    tokenBalanceInPool: null,
    quoteBalanceInPool: null,
    estimatedPoolLiquidityUsd: null,
    estimatedPriceImpactPct: null
  };

  if (poolInfo) {
    const balanceOfData = "0x70a08231" + padAddress(poolInfo.poolAddress);
    const [tokenBalHex, quoteBalHex, v3LiqHex, v2ReservesHex] = await Promise.all([
      safeEthCall(tokenAddress, balanceOfData),
      safeEthCall(poolInfo.quote.address, balanceOfData),
      safeEthCall(poolInfo.poolAddress, "0x1a686502"),
      safeEthCall(poolInfo.poolAddress, "0x0902f1ac")
    ]);

    const tokenBal = decodeUint256(tokenBalHex) ?? 0n;
    const quoteBal = decodeUint256(quoteBalHex) ?? 0n;
    const quoteHuman = Number(quoteBal) / Math.pow(10, poolInfo.quote.decimals);
    const quoteUsdPrice = poolInfo.quote.symbol === "USDC" ? 1 : 2500;
    const oneSideUsd = quoteHuman * quoteUsdPrice;
    const estimatedPoolLiquidityUsd = Math.round(oneSideUsd * 2);

    const tradeUsd = Math.max(1, Number(tradeAmountUsd) || 1000);
    const estimatedPriceImpactPct =
      oneSideUsd > 0 ? Number(((tradeUsd / (oneSideUsd + tradeUsd)) * 100).toFixed(3)) : 100;

    if (estimatedPoolLiquidityUsd < 5000) {
      trapScore += 30;
    } else if (estimatedPoolLiquidityUsd < 25000) {
      trapScore += 15;
    }

    poolMetrics = {
      found: true,
      poolAddress: poolInfo.poolAddress,
      dex: poolInfo.dex,
      feeTierBps: poolInfo.feeTierBps,
      quoteAsset: poolInfo.quote.symbol,
      tokenBalanceRaw: tokenBal.toString(),
      quoteBalanceFormatted: Number(quoteHuman.toFixed(6)),
      hasV3Liquidity: Boolean(v3LiqHex && v3LiqHex !== "0x" && decodeUint256(v3LiqHex) > 0n),
      hasV2Reserves: Boolean(v2ReservesHex && v2ReservesHex !== "0x"),
      estimatedPoolLiquidityUsd,
      estimatedPriceImpactPct
    };
  } else {
    trapScore += 20;
  }

  const honeypotProbability = Math.min(100, Math.max(0, trapScore));
  const action =
    isPaused || honeypotProbability >= 70
      ? "BLOCK"
      : honeypotProbability >= 40 || (poolMetrics.estimatedPriceImpactPct !== null && poolMetrics.estimatedPriceImpactPct > 5)
      ? "WARN"
      : "ALLOW";

  return {
    valid: true,
    engine: "BaseGuard-402 Direct Base RPC Swap Preflight v1.0",
    rpcUrl: codeResult.rpcUrl,
    latencyMs: Date.now() - started,
    tokenAddress,
    tradeAmountUsd: Number(tradeAmountUsd) || 1000,
    verdict: {
      action,
      honeypotProbability,
      estimatedPriceImpactPct: poolMetrics.estimatedPriceImpactPct,
      summary:
        action === "BLOCK"
          ? "HIGH TRAP RISK: Contract paused, severe honeypot bytecode selectors, or zero pool depth."
          : action === "WARN"
          ? "MODERATE RISK: Privileged owner/fee selectors or elevated price impact detected."
          : "CLEAR: Token bytecode & on-chain Base pool reserves pass preflight checks."
    },
    contract: {
      isContract: true,
      symbol,
      decimals: decimalsNum,
      totalSupplyRaw: totalSupplyRaw ? totalSupplyRaw.toString() : null,
      owner: owner || "RENOUNCED_OR_NO_OWNER",
      isPaused,
      isProxyPattern,
      bytecodeBytes: (bytecode.length - 2) / 2,
      bytecodeFlags
    },
    pool: poolMetrics
  };
}
