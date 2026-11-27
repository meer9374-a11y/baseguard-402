import {
  PAY_TO,
  USDC_BASE,
  NETWORK,
  ANTI_REPLAY_WINDOW_SECONDS
} from "./config.js";
import { ethGetTransactionReceipt, ethGetBlockByNumber } from "./rpc.js";

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

export function build402Payload({ resource, amount, usdc, description }) {
  return {
    x402Version: 1,
    error: "Payment Required",
    payTo: PAY_TO,
    network: NETWORK,
    asset: USDC_BASE,
    amount: String(amount),
    priceUsd: `$${usdc} USDC`,
    maxTimeoutSeconds: ANTI_REPLAY_WINDOW_SECONDS,
    accepts: [
      {
        scheme: "exact",
        network: NETWORK,
        maxAmountRequired: String(amount),
        resource,
        description,
        mimeType: "application/json",
        payTo: PAY_TO,
        maxTimeoutSeconds: ANTI_REPLAY_WINDOW_SECONDS,
        asset: USDC_BASE,
        extra: {
          name: "USD Coin",
          version: "2",
          decimals: 6,
          priceUsd: `$${usdc}`
        }
      }
    ],
    instructions: {
      payment: `Send at least ${usdc} USDC (${amount} base units) on Base Mainnet to ${PAY_TO}`,
      retryHeader: "X-Payment-Tx: <0x_base_tx_hash>",
      freeDemo: "Append ?demo=true for an edge-cached preview (60s CDN cache)"
    }
  };
}

export async function verifyX402Payment(txHash, requiredBaseUnits) {
  if (!txHash || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
    return {
      valid: false,
      code: "INVALID_TX_HASH",
      reason: "X-Payment-Tx must be a valid 66-character 0x-prefixed Base transaction hash."
    };
  }

  let receiptData;
  try {
    receiptData = await ethGetTransactionReceipt(txHash);
  } catch (err) {
    return {
      valid: false,
      code: "RPC_UNAVAILABLE",
      reason: `Failed to query Base RPC for transaction receipt: ${err.message}`
    };
  }

  const receipt = receiptData.receipt;
  if (!receipt) {
    return {
      valid: false,
      code: "TX_NOT_FOUND",
      reason: "Transaction not found or not yet confirmed on Base Mainnet."
    };
  }

  if (receipt.status !== "0x1") {
    return {
      valid: false,
      code: "TX_REVERTED",
      reason: `Transaction status is ${receipt.status} (expected 0x1).`
    };
  }

  const targetUsdc = USDC_BASE.toLowerCase();
  const targetRecipientPadded = "0x" + PAY_TO.toLowerCase().replace(/^0x/, "").padStart(64, "0");
  const required = BigInt(requiredBaseUnits);

  let matchedTransfer = null;
  for (const log of receipt.logs || []) {
    if (!log || !log.address || !Array.isArray(log.topics) || log.topics.length < 3) continue;
    if (log.address.toLowerCase() !== targetUsdc) continue;
    if (log.topics[0].toLowerCase() !== TRANSFER_TOPIC) continue;
    if (log.topics[2].toLowerCase() !== targetRecipientPadded) continue;

    const amount = BigInt(log.data || "0x0");
    if (amount >= required) {
      matchedTransfer = {
        payer: "0x" + log.topics[1].slice(26),
        amountPaid: amount.toString()
      };
      break;
    }
  }

  if (!matchedTransfer) {
    return {
      valid: false,
      code: "INSUFFICIENT_OR_MISSING_USDC_TRANSFER",
      reason: `No Base USDC Transfer log >= ${requiredBaseUnits} base units to ${PAY_TO} found in tx ${txHash}.`
    };
  }

  let blockData;
  try {
    blockData = await ethGetBlockByNumber(receipt.blockNumber);
  } catch (err) {
    return {
      valid: false,
      code: "BLOCK_LOOKUP_FAILED",
      reason: `Failed to verify block timestamp for anti-replay: ${err.message}`
    };
  }

  const block = blockData.block;
  if (!block || !block.timestamp) {
    return {
      valid: false,
      code: "BLOCK_NOT_FOUND",
      reason: "Could not resolve block timestamp for anti-replay verification."
    };
  }

  const blockTimestamp = parseInt(block.timestamp, 16);
  const nowSec = Math.floor(Date.now() / 1000);
  const ageSeconds = nowSec - blockTimestamp;

  if (ageSeconds > ANTI_REPLAY_WINDOW_SECONDS) {
    return {
      valid: false,
      code: "PAYMENT_EXPIRED_REPLAY_GUARD",
      reason: `Payment transaction is ${ageSeconds}s old (max ${ANTI_REPLAY_WINDOW_SECONDS}s stateless anti-replay window).`
    };
  }

  return {
    valid: true,
    txHash,
    payer: matchedTransfer.payer,
    amountPaid: matchedTransfer.amountPaid,
    requiredAmount: String(requiredBaseUnits),
    blockNumber: parseInt(receipt.blockNumber, 16),
    blockTimestamp,
    ageSeconds: Math.max(0, ageSeconds),
    rpcUrl: receiptData.rpcUrl
  };
}
