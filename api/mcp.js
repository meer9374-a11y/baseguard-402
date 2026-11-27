import {
  PAY_TO,
  USDC_BASE,
  PRICING,
  setCorsHeaders,
  getPaymentTxHeader,
  parseRequestBody,
  getRequestOrigin
} from "../lib/config.js";
import { build402Payload, verifyX402Payment } from "../lib/x402.js";
import { analyzeCalldata } from "../lib/calldata-analyzer.js";
import { simulateBaseSwapPreflight } from "../lib/swap-simulator.js";
import { scanBaseTokenIntel } from "../lib/token-intel.js";

const PROTOCOL_VERSION = "2024-11-05";

const TOOLS = [
  {
    name: "audit_evm_calldata",
    description:
      "Deterministic EVM calldata & ABI selector pre-trade firewall ($0.003 USDC / 3000 base units on Base, zero external API limits). Flags unlimited approve(MAX_UINT256), setApprovalForAll drainers, EIP-2612 permit phishing, and proxy upgrades. Pass demo=true for edge-cached preview or payment_tx for paid execution.",
    inputSchema: {
      type: "object",
      properties: {
        calldata: {
          type: "string",
          description: "0x-prefixed EVM transaction calldata hex string"
        },
        to: {
          type: "string",
          description: "Optional 0x-prefixed target contract address"
        },
        value: {
          type: "string",
          description: "Optional native ETH value in wei (default '0')"
        },
        payment_tx: {
          type: "string",
          description: "Base Mainnet USDC payment transaction hash (0x...) paying >= 0.003 USDC to payTo"
        },
        demo: {
          type: "boolean",
          description: "Set true for free edge-cached demo preview"
        }
      },
      required: ["calldata"]
    }
  },
  {
    name: "simulate_base_swap_preflight",
    description:
      "Direct Base Mainnet RPC swap preflight simulator ($0.005 USDC / 5000 base units on Base). Scans deployed token bytecode for pause/blacklist/tax/proxy traps and queries Uniswap V3 / pool reserves to estimate price impact and honeypot probability before trade execution.",
    inputSchema: {
      type: "object",
      properties: {
        tokenAddress: {
          type: "string",
          description: "0x-prefixed Base ERC-20 token contract address"
        },
        poolAddress: {
          type: "string",
          description: "Optional 0x-prefixed Uniswap V3 or Aerodrome pool address"
        },
        tradeAmountUsd: {
          type: "number",
          description: "Planned swap size in USD (default 1000)"
        },
        payment_tx: {
          type: "string",
          description: "Base Mainnet USDC payment transaction hash (0x...) paying >= 0.005 USDC to payTo"
        },
        demo: {
          type: "boolean",
          description: "Set true for free edge-cached demo preview"
        }
      },
      required: ["tokenAddress"]
    }
  },
  {
    name: "scan_base_token_intel",
    description:
      "Edge-cached Base token liquidity & security aggregator ($0.005 USDC / 5000 base units on Base). Combines DexScreener liquidity/volume/price with GoPlus Security honeypot, buy/sell tax, and contract ownership signals.",
    inputSchema: {
      type: "object",
      properties: {
        tokenAddress: {
          type: "string",
          description: "0x-prefixed Base ERC-20 token contract address"
        },
        payment_tx: {
          type: "string",
          description: "Base Mainnet USDC payment transaction hash (0x...) paying >= 0.005 USDC to payTo"
        },
        demo: {
          type: "boolean",
          description: "Set true for free edge-cached demo preview"
        }
      },
      required: ["tokenAddress"]
    }
  }
];

function jsonRpcResult(id, result) {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function jsonRpcError(id, code, message, data = undefined) {
  const err = { code, message };
  if (data !== undefined) err.data = data;
  return { jsonrpc: "2.0", id: id ?? null, error: err };
}

export default async function handler(req, res) {
  setCorsHeaders(res);
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  // Informative GET response for MCP endpoint health & discovery
  if (req.method === "GET") {
    res.setHeader("Cache-Control", "public, s-maxage=60, stale-while-revalidate=120");
    return res.status(200).json({
      name: "baseguard-402",
      protocol: "MCP JSON-RPC 2.0",
      protocolVersion: PROTOCOL_VERSION,
      transport: "streamable-http",
      endpoint: "/mcp",
      payTo: PAY_TO,
      asset: USDC_BASE,
      network: "base",
      tools: TOOLS.map((t) => t.name),
      usage: "Send HTTP POST with JSON-RPC 2.0 body (initialize, tools/list, tools/call)."
    });
  }

  const body = await parseRequestBody(req);
  if (!body || body.jsonrpc !== "2.0" || !body.method) {
    return res.status(400).json(jsonRpcError(body?.id, -32600, "Invalid JSON-RPC 2.0 request"));
  }

  const { id, method, params = {} } = body;

  if (method === "initialize") {
    return res.status(200).json(
      jsonRpcResult(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {
          tools: { listChanged: false }
        },
        serverInfo: {
          name: "baseguard-402",
          version: "1.0.0"
        }
      })
    );
  }

  if (method === "notifications/initialized") {
    return res.status(202).end();
  }

  if (method === "ping") {
    return res.status(200).json(jsonRpcResult(id, {}));
  }

  if (method === "tools/list") {
    return res.status(200).json(jsonRpcResult(id, { tools: TOOLS }));
  }

  if (method === "tools/call") {
    const toolName = params.name;
    const args = params.arguments || {};
    const headerTx = getPaymentTxHeader(req);
    const paymentTx = (args.payment_tx || headerTx || "").toString().trim();
    const demo = Boolean(args.demo);
    const origin = getRequestOrigin(req);

    const specMap = {
      audit_evm_calldata: PRICING["calldata-firewall"],
      simulate_base_swap_preflight: PRICING["swap-preflight"],
      scan_base_token_intel: PRICING["token-intel"]
    };

    const spec = specMap[toolName];
    if (!spec) {
      return res.status(200).json(jsonRpcError(id, -32601, `Unknown tool: ${toolName}`));
    }

    let paymentInfo = null;
    if (paymentTx) {
      const verification = await verifyX402Payment(paymentTx, spec.amount);
      if (!verification.valid) {
        const paymentRequired = {
          ...build402Payload({
            resource: `${origin}${spec.endpoint}`,
            amount: spec.amount,
            usdc: spec.usdc,
            description: spec.description
          }),
          paymentVerificationError: verification
        };
        return res.status(200).json(
          jsonRpcResult(id, {
            isError: true,
            content: [{ type: "text", text: JSON.stringify(paymentRequired, null, 2) }]
          })
        );
      }
      paymentInfo = verification;
    } else if (!demo) {
      const paymentRequired = build402Payload({
        resource: `${origin}${spec.endpoint}`,
        amount: spec.amount,
        usdc: spec.usdc,
        description: spec.description
      });
      return res.status(200).json(
        jsonRpcResult(id, {
          isError: true,
          content: [{ type: "text", text: JSON.stringify(paymentRequired, null, 2) }]
        })
      );
    }

    let output;
    try {
      if (toolName === "audit_evm_calldata") {
        output = analyzeCalldata({
          calldata: args.calldata,
          to: args.to || null,
          value: args.value || "0"
        });
      } else if (toolName === "simulate_base_swap_preflight") {
        output = await simulateBaseSwapPreflight({
          tokenAddress: args.tokenAddress,
          poolAddress: args.poolAddress || null,
          tradeAmountUsd: args.tradeAmountUsd || 1000
        });
      } else if (toolName === "scan_base_token_intel") {
        output = await scanBaseTokenIntel(args.tokenAddress);
      }
    } catch (err) {
      return res.status(200).json(
        jsonRpcResult(id, {
          isError: true,
          content: [{ type: "text", text: JSON.stringify({ error: err.message }, null, 2) }]
        })
      );
    }

    const payload = {
      mode: paymentInfo ? "paid" : "demo_edge_cached",
      ...(paymentInfo ? { payment: paymentInfo } : {}),
      ...output
    };

    return res.status(200).json(
      jsonRpcResult(id, {
        isError: !output.valid,
        content: [{ type: "text", text: JSON.stringify(payload, null, 2) }]
      })
    );
  }

  return res.status(200).json(jsonRpcError(id, -32601, `Method not found: ${method}`));
}
