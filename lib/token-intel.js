const FETCH_TIMEOUT_MS = 6500;

function isValidAddress(addr) {
  return typeof addr === "string" && /^0x[0-9a-fA-F]{40}$/.test(addr);
}

async function fetchJsonWithTimeout(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": "BaseGuard-402/1.0" },
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) return { ok: false, status: res.status, data: null };
    return { ok: true, status: res.status, data: await res.json() };
  } catch (err) {
    clearTimeout(timer);
    return { ok: false, status: 0, error: err.message, data: null };
  }
}

export async function scanBaseTokenIntel(tokenAddress) {
  if (!isValidAddress(tokenAddress)) {
    return {
      valid: false,
      error: "Invalid tokenAddress. Expected 42-character 0x-prefixed Base token address."
    };
  }

  const lower = tokenAddress.toLowerCase();
  const started = Date.now();

  const [dexRes, goPlusRes] = await Promise.all([
    fetchJsonWithTimeout(`https://api.dexscreener.com/latest/dex/tokens/${tokenAddress}`),
    fetchJsonWithTimeout(`https://api.gopluslabs.io/api/v1/token_security/8453?contract_addresses=${lower}`)
  ]);

  const allPairs = Array.isArray(dexRes.data?.pairs) ? dexRes.data.pairs : [];
  const basePairs = allPairs
    .filter((p) => (p.chainId || "").toLowerCase() === "base")
    .sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));

  const topPair = basePairs[0] || null;
  const dexIntel = topPair
    ? {
        available: true,
        pairCountOnBase: basePairs.length,
        dexId: topPair.dexId,
        pairAddress: topPair.pairAddress,
        baseToken: {
          symbol: topPair.baseToken?.symbol,
          name: topPair.baseToken?.name,
          address: topPair.baseToken?.address
        },
        quoteToken: topPair.quoteToken?.symbol,
        priceUsd: topPair.priceUsd ? Number(topPair.priceUsd) : null,
        liquidityUsd: topPair.liquidity?.usd ?? 0,
        volume24hUsd: topPair.volume?.h24 ?? 0,
        fdvUsd: topPair.fdv ?? null,
        priceChange24hPct: topPair.priceChange?.h24 ?? null,
        pairCreatedAt: topPair.pairCreatedAt || null
      }
    : {
        available: false,
        pairCountOnBase: 0,
        note: "No active Base DEX pairs indexed on DexScreener."
      };

  const gpToken = goPlusRes.data?.result?.[lower] || null;
  const securityIntel = gpToken
    ? {
        available: true,
        isHoneypot: gpToken.is_honeypot === "1",
        buyTaxPct: Number(((Number(gpToken.buy_tax) || 0) * 100).toFixed(2)),
        sellTaxPct: Number(((Number(gpToken.sell_tax) || 0) * 100).toFixed(2)),
        isOpenSource: gpToken.is_open_source === "1",
        isProxy: gpToken.is_proxy === "1",
        isMintable: gpToken.is_mintable === "1",
        cannotSellAll: gpToken.cannot_sell_all === "1",
        isBlacklisted: gpToken.is_blacklisted === "1",
        ownerChangeBalance: gpToken.owner_change_balance === "1",
        holderCount: gpToken.holder_count ? Number(gpToken.holder_count) : null
      }
    : {
        available: false,
        note: "GoPlus Security data temporarily unavailable for this token."
      };

  let riskScore = 10;
  const flags = [];

  if (securityIntel.available) {
    if (securityIntel.isHoneypot) {
      riskScore += 90;
      flags.push("GOPLUS_HONEYPOT_CONFIRMED");
    }
    if (securityIntel.cannotSellAll) {
      riskScore += 50;
      flags.push("CANNOT_SELL_ALL");
    }
    if (securityIntel.sellTaxPct > 10) {
      riskScore += 40;
      flags.push(`HIGH_SELL_TAX_${securityIntel.sellTaxPct}%`);
    }
    if (securityIntel.buyTaxPct > 10) {
      riskScore += 25;
      flags.push(`HIGH_BUY_TAX_${securityIntel.buyTaxPct}%`);
    }
    if (!securityIntel.isOpenSource) {
      riskScore += 20;
      flags.push("UNVERIFIED_SOURCE_CODE");
    }
    if (securityIntel.ownerChangeBalance) {
      riskScore += 35;
      flags.push("OWNER_CAN_MUTATE_BALANCES");
    }
    if (securityIntel.isMintable) {
      riskScore += 10;
      flags.push("MINTABLE_SUPPLY");
    }
  }

  if (dexIntel.available) {
    if (dexIntel.liquidityUsd < 5000) {
      riskScore += 35;
      flags.push("ULTRA_LOW_LIQUIDITY");
    } else if (dexIntel.liquidityUsd < 25000) {
      riskScore += 15;
      flags.push("LOW_LIQUIDITY");
    }
  } else {
    riskScore += 25;
    flags.push("NO_INDEXED_BASE_DEX_POOL");
  }

  riskScore = Math.min(100, Math.max(0, riskScore));
  const action = riskScore >= 65 ? "BLOCK" : riskScore >= 35 ? "WARN" : "ALLOW";

  return {
    valid: true,
    engine: "BaseGuard-402 Edge-Cached Token Intel v1.0",
    chain: "base",
    chainId: 8453,
    tokenAddress,
    latencyMs: Date.now() - started,
    edgeCacheTtlSeconds: 15,
    verdict: {
      action,
      riskScore,
      flags
    },
    dexscreener: dexIntel,
    goplus: securityIntel
  };
}
