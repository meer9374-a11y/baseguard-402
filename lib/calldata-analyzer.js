const KNOWN_BASE_SAFE_ROUTERS = {
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router (Base)",
  "0x6ff5693b99212da76ad316178a184ab56d299b43": "Uniswap Universal Router V2 (Base)",
  "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap V3 SwapRouter02 (Base)",
  "0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43": "Aerodrome Router (Base)",
  "0xbe6d8f0d05cc4be24d5167a3ef062215be6d18a5": "Aerodrome Slipstream Router (Base)",
  "0x000000000022d473030f116ddee9f6b43ac78ba3": "Uniswap Permit2 (Canonical)",
  "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy (Base)",
  "0x111111125421ca6dc452d289314280a0f8842a65": "1inch Aggregation Router v6",
  "0x9008d19f58aabd9ed0d60971565aa8510560ab41": "CoW Protocol Settlement"
};

const KNOWN_SELECTORS = {
  "0x095ea7b3": { name: "approve", signature: "approve(address,uint256)", category: "APPROVAL" },
  "0xa22cb465": { name: "setApprovalForAll", signature: "setApprovalForAll(address,bool)", category: "APPROVAL" },
  "0xd505accf": { name: "permit", signature: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", category: "PERMIT" },
  "0x39509351": { name: "increaseAllowance", signature: "increaseAllowance(address,uint256)", category: "APPROVAL" },
  "0x3659cfe6": { name: "upgradeTo", signature: "upgradeTo(address)", category: "PROXY_UPGRADE" },
  "0x4f1ef286": { name: "upgradeToAndCall", signature: "upgradeToAndCall(address,bytes)", category: "PROXY_UPGRADE" },
  "0x8f283970": { name: "changeAdmin", signature: "changeAdmin(address)", category: "PROXY_ADMIN" },
  "0xf2fde38b": { name: "transferOwnership", signature: "transferOwnership(address)", category: "ADMIN" },
  "0x23b872dd": { name: "transferFrom", signature: "transferFrom(address,address,uint256)", category: "TRANSFER" },
  "0xa9059cbb": { name: "transfer", signature: "transfer(address,uint256)", category: "TRANSFER" },
  "0x42842e0e": { name: "safeTransferFrom", signature: "safeTransferFrom(address,address,uint256)", category: "NFT_TRANSFER" },
  "0xac9650d8": { name: "multicall", signature: "multicall(bytes[])", category: "MULTICALL" },
  "0x5ae401dc": { name: "multicall", signature: "multicall(uint256,bytes[])", category: "MULTICALL" },
  "0x3593564c": { name: "execute", signature: "execute(bytes,bytes[],uint256)", category: "SWAP_ROUTER" },
  "0x414bf389": { name: "exactInputSingle", signature: "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))", category: "SWAP_ROUTER" },
  "0x04e45aaf": { name: "exactInputSingle", signature: "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))", category: "SWAP_ROUTER" },
  "0x4e71d92d": { name: "claim", signature: "claim()", category: "DRAINER_SUSPECT" },
  "0x53a47bb7": { name: "securityUpdate", signature: "securityUpdate()", category: "DRAINER_SUSPECT" },
  "0x1c1b8772": { name: "claimRewards", signature: "claimRewards()", category: "DRAINER_SUSPECT" }
};

const MAX_UINT256_THRESHOLD = (1n << 255n);

function normalizeHex(hex) {
  if (!hex || typeof hex !== "string") return "";
  const cleaned = hex.trim().toLowerCase();
  if (!cleaned.startsWith("0x")) return "";
  return /^0x[0-9a-f]*$/.test(cleaned) ? cleaned : "";
}

function readWord(hexBody, wordIndex) {
  const start = wordIndex * 64;
  const end = start + 64;
  if (hexBody.length < end) return null;
  return hexBody.slice(start, end);
}

function wordToAddress(word) {
  if (!word || word.length !== 64) return null;
  return "0x" + word.slice(24);
}

function wordToBigInt(word) {
  if (!word || word.length !== 64) return null;
  return BigInt("0x" + word);
}

export function analyzeCalldata({ calldata, to = null, value = "0", chain = "base" }) {
  const normalized = normalizeHex(calldata);
  if (!normalized || normalized.length < 10) {
    return {
      valid: false,
      error: "Invalid calldata. Expected 0x-prefixed hex string with at least a 4-byte function selector (10+ chars)."
    };
  }

  const selector = normalized.slice(0, 10);
  const body = normalized.slice(10);
  const byteLength = (normalized.length - 2) / 2;
  const known = KNOWN_SELECTORS[selector] || null;

  const findings = [];
  let riskScore = 5;
  const decoded = {
    selector,
    functionName: known ? known.name : "unknown",
    signature: known ? known.signature : "unknown(bytes)",
    category: known ? known.category : "UNKNOWN",
    byteLength,
    params: {}
  };

  if (selector === "0x095ea7b3" || selector === "0x39509351") {
    const spender = wordToAddress(readWord(body, 0));
    const amount = wordToBigInt(readWord(body, 1));
    const knownRouter = spender ? KNOWN_BASE_SAFE_ROUTERS[spender.toLowerCase()] : null;

    decoded.params = {
      spender,
      amount: amount !== null ? amount.toString() : null,
      isUnlimited: amount !== null ? amount >= MAX_UINT256_THRESHOLD : false,
      spenderLabel: knownRouter || "UNVERIFIED_EXTERNAL_SPENDER"
    };

    if (amount !== null && amount >= MAX_UINT256_THRESHOLD) {
      riskScore += knownRouter ? 35 : 75;
      findings.push({
        id: "UNLIMITED_ERC20_APPROVAL",
        severity: knownRouter ? "MEDIUM" : "CRITICAL",
        message: knownRouter
          ? `Unlimited ERC-20 approval (MAX_UINT256) granted to known router: ${knownRouter}. Prefer exact-amount approvals.`
          : `CRITICAL: Unlimited ERC-20 approval (MAX_UINT256 / 2^256-1) to unverified spender ${spender}. High wallet drainer risk.`
      });
    } else if (spender && !knownRouter) {
      riskScore += 40;
      findings.push({
        id: "UNVERIFIED_APPROVAL_SPENDER",
        severity: "HIGH",
        message: `Token approval targets unverified spender ${spender} (not in Base canonical router allowlist).`
      });
    } else if (knownRouter) {
      findings.push({
        id: "EXACT_APPROVAL_KNOWN_ROUTER",
        severity: "LOW",
        message: `Bounded approval targets verified Base router: ${knownRouter}.`
      });
    }
  }

  if (selector === "0xa22cb465") {
    const operator = wordToAddress(readWord(body, 0));
    const approvedWord = wordToBigInt(readWord(body, 1));
    const approved = approvedWord !== null && approvedWord !== 0n;
    const knownRouter = operator ? KNOWN_BASE_SAFE_ROUTERS[operator.toLowerCase()] : null;

    decoded.params = {
      operator,
      approved,
      operatorLabel: knownRouter || "UNVERIFIED_OPERATOR"
    };

    if (approved && !knownRouter) {
      riskScore += 85;
      findings.push({
        id: "NFT_SET_APPROVAL_FOR_ALL_DRAINER",
        severity: "CRITICAL",
        message: `CRITICAL: setApprovalForAll(true) grants full control of all NFTs in collection to unverified operator ${operator}.`
      });
    } else if (approved && knownRouter) {
      riskScore += 25;
      findings.push({
        id: "NFT_APPROVAL_KNOWN_OPERATOR",
        severity: "MEDIUM",
        message: `setApprovalForAll(true) targets known contract ${knownRouter}. Verify marketplace intent.`
      });
    }
  }

  if (selector === "0xd505accf") {
    const owner = wordToAddress(readWord(body, 0));
    const spender = wordToAddress(readWord(body, 1));
    const permitValue = wordToBigInt(readWord(body, 2));
    const deadline = wordToBigInt(readWord(body, 3));
    const knownRouter = spender ? KNOWN_BASE_SAFE_ROUTERS[spender.toLowerCase()] : null;
    const isUnlimited = permitValue !== null && permitValue >= MAX_UINT256_THRESHOLD;

    decoded.params = {
      owner,
      spender,
      value: permitValue !== null ? permitValue.toString() : null,
      deadline: deadline !== null ? deadline.toString() : null,
      isUnlimited,
      spenderLabel: knownRouter || "UNVERIFIED_PERMIT_SPENDER"
    };

    if (!knownRouter) {
      riskScore += isUnlimited ? 80 : 55;
      findings.push({
        id: "EIP2612_PERMIT_PHISHING_RISK",
        severity: "CRITICAL",
        message: `Gasless EIP-2612 permit() grants ${isUnlimited ? "UNLIMITED" : "token"} allowance to unverified spender ${spender}. Common phishing drainer vector.`
      });
    } else if (isUnlimited) {
      riskScore += 30;
      findings.push({
        id: "EIP2612_UNLIMITED_PERMIT",
        severity: "MEDIUM",
        message: `Unlimited permit() allowance to ${knownRouter}. Recommend scoping permit value to exact swap amount.`
      });
    }
  }

  if (["0x3659cfe6", "0x4f1ef286", "0x8f283970", "0xf2fde38b"].includes(selector)) {
    const targetAddr = wordToAddress(readWord(body, 0));
    decoded.params = { newImplementationOrAdmin: targetAddr };
    riskScore += 90;
    findings.push({
      id: "PRIVILEGED_PROXY_OR_ADMIN_MUTATION",
      severity: "CRITICAL",
      message: `CRITICAL: Privileged ${known.signature} call targeting ${targetAddr || "unknown"}. Autonomous trading agents should never sign proxy/admin mutations.`
    });
  }

  if (known && known.category === "DRAINER_SUSPECT") {
    riskScore += 70;
    findings.push({
      id: "PHISHING_DECOY_SELECTOR",
      severity: "HIGH",
      message: `Selector ${selector} (${known.signature}) matches high-frequency airdrop/securityUpdate phishing drainer decoys.`
    });
  }

  if (selector === "0xa9059cbb" || selector === "0x23b872dd") {
    const isFrom = selector === "0x23b872dd";
    const fromAddr = isFrom ? wordToAddress(readWord(body, 0)) : null;
    const toAddr = wordToAddress(readWord(body, isFrom ? 1 : 0));
    const amount = wordToBigInt(readWord(body, isFrom ? 2 : 1));
    decoded.params = {
      ...(fromAddr ? { from: fromAddr } : {}),
      to: toAddr,
      amount: amount !== null ? amount.toString() : null
    };
    riskScore += 20;
    findings.push({
      id: "DIRECT_ASSET_OUTFLOW",
      severity: "MEDIUM",
      message: `Direct ERC-20 ${known.name} sending ${amount?.toString() || "unknown"} base units to ${toAddr}. Verify recipient before signing.`
    });
  }

  if (selector === "0xac9650d8" || selector === "0x5ae401dc") {
    const nestedThreats = [];
    if (body.includes("095ea7b3")) nestedThreats.push("approve(0x095ea7b3)");
    if (body.includes("a22cb465")) nestedThreats.push("setApprovalForAll(0xa22cb465)");
    if (body.includes("d505accf")) nestedThreats.push("permit(0xd505accf)");
    if (body.includes("3659cfe6") || body.includes("4f1ef286")) nestedThreats.push("upgradeTo");

    decoded.params = { nestedSuspiciousSelectors: nestedThreats };
    if (nestedThreats.length > 0) {
      riskScore += 65;
      findings.push({
        id: "MULTICALL_NESTED_APPROVAL_OR_UPGRADE",
        severity: "HIGH",
        message: `Multicall payload embeds high-risk inner selectors: ${nestedThreats.join(", ")}.`
      });
    } else {
      riskScore += 15;
      findings.push({
        id: "MULTICALL_BATCH_EXECUTION",
        severity: "LOW",
        message: "Batched multicall execution detected. Verify target router contract."
      });
    }
  }

  if (!known) {
    riskScore += 25;
    findings.push({
      id: "UNRECOGNIZED_SELECTOR",
      severity: "MEDIUM",
      message: `Function selector ${selector} is not in standard ERC-20/DEX ABI registry. Inspect target contract ABI before signing.`
    });
  }

  if (!known && body.includes("ffffffffffffffffffffffffffffffff")) {
    riskScore += 20;
    findings.push({
      id: "MAX_UINT_CONSTANT_IN_UNKNOWN_CALL",
      severity: "MEDIUM",
      message: "Unrecognized calldata contains MAX_UINT bitmask (ffff...), often used in custom approval drainers."
    });
  }

  const targetLabel = to ? KNOWN_BASE_SAFE_ROUTERS[to.toLowerCase()] || null : null;
  if (targetLabel && riskScore < 50) {
    riskScore = Math.max(5, riskScore - 10);
  }

  riskScore = Math.min(100, Math.max(0, riskScore));

  let severity = "LOW";
  let action = "ALLOW";
  if (riskScore >= 75) {
    severity = "CRITICAL";
    action = "BLOCK";
  } else if (riskScore >= 50) {
    severity = "HIGH";
    action = "BLOCK";
  } else if (riskScore >= 25) {
    severity = "MEDIUM";
    action = "WARN";
  }

  const recommendation =
    action === "BLOCK"
      ? "DO NOT SIGN. Reject transaction immediately — high probability of unlimited approval drain, phishing permit, or privileged hijack."
      : action === "WARN"
      ? "CAUTION. Verify spender/recipient address and bound approval amount to exact swap size before execution."
      : "SAFE TO PROCEED. Calldata matches standard bounded DeFi interaction.";

  return {
    valid: true,
    engine: "BaseGuard-402 Deterministic Calldata Firewall v1.0",
    externalApiCalls: 0,
    chain,
    target: to,
    targetLabel,
    valueWei: String(value || "0"),
    verdict: {
      action,
      severity,
      riskScore
    },
    decoded,
    findings,
    recommendation
  };
}
