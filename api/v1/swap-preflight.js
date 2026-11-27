import {
  PRICING,
  WETH_BASE,
  setCorsHeaders,
  setDemoCacheHeaders,
  setNoCacheHeaders,
  getPaymentTxHeader,
  isDemoRequest,
  parseRequestBody,
  getRequestOrigin
} from "../../lib/config.js";
import { build402Payload, verifyX402Payment } from "../../lib/x402.js";
import { simulateBaseSwapPreflight } from "../../lib/swap-simulator.js";

const SPEC = PRICING["swap-preflight"];
const DEFAULT_DEMO_TOKEN = "0x532f27101965dd16442E59d40670FaF5eBB142E4";

export default async function handler(req, res) {
  setCorsHeaders(res);
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  const demo = isDemoRequest(req);
  const paymentTx = getPaymentTxHeader(req);
  const body = await parseRequestBody(req);
  const query = req.query || {};

  const tokenAddress = body.tokenAddress || body.token || query.tokenAddress || query.token || (demo ? DEFAULT_DEMO_TOKEN : "");
  const poolAddress = body.poolAddress || query.poolAddress || null;
  const tradeAmountUsd = Number(body.tradeAmountUsd || query.tradeAmountUsd || 1000);

  if (paymentTx) {
    setNoCacheHeaders(res);
    const verification = await verifyX402Payment(paymentTx, SPEC.amount);
    if (!verification.valid) {
      return res.status(402).json({
        ...build402Payload({
          resource: `${getRequestOrigin(req)}${SPEC.endpoint}`,
          amount: SPEC.amount,
          usdc: SPEC.usdc,
          description: SPEC.description
        }),
        paymentVerificationError: verification
      });
    }

    const result = await simulateBaseSwapPreflight({
      tokenAddress: tokenAddress || WETH_BASE,
      poolAddress,
      tradeAmountUsd
    });
    if (!result.valid) {
      return res.status(400).json({ error: result.error });
    }

    return res.status(200).json({
      mode: "paid",
      payment: verification,
      ...result
    });
  }

  if (demo) {
    setDemoCacheHeaders(res);
    const result = await simulateBaseSwapPreflight({
      tokenAddress,
      poolAddress,
      tradeAmountUsd
    });
    if (!result.valid) {
      return res.status(400).json({ error: result.error });
    }

    return res.status(200).json({
      mode: "demo_edge_cached",
      cacheControl: "public, s-maxage=60, stale-while-revalidate=120",
      upgradeNote: `Send ${SPEC.usdc} USDC on Base with X-Payment-Tx header for real-time uncached preflight simulation.`,
      ...result
    });
  }

  setNoCacheHeaders(res);
  return res.status(402).json(
    build402Payload({
      resource: `${getRequestOrigin(req)}${SPEC.endpoint}`,
      amount: SPEC.amount,
      usdc: SPEC.usdc,
      description: SPEC.description
    })
  );
}
