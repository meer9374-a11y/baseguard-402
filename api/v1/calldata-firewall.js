import {
  PRICING,
  setCorsHeaders,
  setDemoCacheHeaders,
  setNoCacheHeaders,
  getPaymentTxHeader,
  isDemoRequest,
  parseRequestBody,
  getRequestOrigin
} from "../../lib/config.js";
import { build402Payload, verifyX402Payment } from "../../lib/x402.js";
import { analyzeCalldata } from "../../lib/calldata-analyzer.js";

const SPEC = PRICING["calldata-firewall"];

const DEFAULT_DEMO_CALLDATA =
  "0x095ea7b3000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" +
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

export default async function handler(req, res) {
  setCorsHeaders(res);
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  const demo = isDemoRequest(req);
  const paymentTx = getPaymentTxHeader(req);
  const body = await parseRequestBody(req);
  const query = req.query || {};

  const calldata = body.calldata || query.calldata || (demo ? DEFAULT_DEMO_CALLDATA : "");
  const to = body.to || query.to || (demo ? "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" : null);
  const value = body.value || query.value || "0";

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

    const analysis = analyzeCalldata({ calldata, to, value });
    if (!analysis.valid) {
      return res.status(400).json({ error: analysis.error });
    }

    return res.status(200).json({
      mode: "paid",
      payment: verification,
      ...analysis
    });
  }

  if (demo) {
    setDemoCacheHeaders(res);
    const analysis = analyzeCalldata({ calldata, to, value });
    if (!analysis.valid) {
      return res.status(400).json({ error: analysis.error });
    }

    return res.status(200).json({
      mode: "demo_edge_cached",
      cacheControl: "public, s-maxage=60, stale-while-revalidate=120",
      upgradeNote: `Send ${SPEC.usdc} USDC on Base to bypass demo caching and unlock production SLA.`,
      ...analysis
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
