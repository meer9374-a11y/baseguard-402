import {
  PRICING,
  setCorsHeaders,
  setDemoCacheHeaders,
  setPaidEdgeCacheHeaders,
  setNoCacheHeaders,
  getPaymentTxHeader,
  isDemoRequest,
  parseRequestBody,
  getRequestOrigin
} from "../../lib/config.js";
import { build402Payload, verifyX402Payment } from "../../lib/x402.js";
import { scanBaseTokenIntel } from "../../lib/token-intel.js";

const SPEC = PRICING["token-intel"];
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

  if (paymentTx) {
    const verification = await verifyX402Payment(paymentTx, SPEC.amount);
    if (!verification.valid) {
      setNoCacheHeaders(res);
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

    setPaidEdgeCacheHeaders(res);
    const result = await scanBaseTokenIntel(tokenAddress);
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
    const result = await scanBaseTokenIntel(tokenAddress);
    if (!result.valid) {
      return res.status(400).json({ error: result.error });
    }

    return res.status(200).json({
      mode: "demo_edge_cached",
      cacheControl: "public, s-maxage=60, stale-while-revalidate=120",
      upgradeNote: `Send ${SPEC.usdc} USDC on Base with X-Payment-Tx header for 15s-fresh production intel.`,
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
