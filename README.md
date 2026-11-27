# BaseGuard-402

Ultra-Low-Cost Remote MCP & x402 Pre-Trade Firewall on Base ($0.003??0.005 USDC, Zero API Keys): Real-time EVM calldata phishing firewall, on-chain swap preflight simulation, honeypot detector, and edge-cached liquidity scanner with ready-to-use Coinbase AgentKit, ElizaOS, and Claude/Cursor plugins.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Network: Base Mainnet](https://img.shields.io/badge/Network-Base%20Mainnet%20(8453)-0052FF.svg)](https://base.org)
[![Protocol: x402 + MCP](https://img.shields.io/badge/Protocol-x402%20%2B%20MCP%202024--11--05-10B981.svg)](https://baseguard-402.vercel.app/mcp)
[![Dependencies: Zero](https://img.shields.io/badge/Dependencies-0%20npm%20packages-8B5CF6.svg)](package.json)

---

## Why BaseGuard-402?

Autonomous trading bots on Base lose millions to **unlimited `approve(MAX_UINT256)` drainers**, **EIP-2612 `permit` phishing**, and **honeypot tokens**?”while legacy security APIs charge $0.01??0.05/call or gate access behind API keys and subscriptions.

**BaseGuard-402** undercuts the market with **stateless x402 micro-payments on Base L2**:
- **Zero API keys, zero signups, zero external npm dependencies** (pure Node.js ES Modules + Web Standard `fetch`).
- **Stateless Base Mainnet USDC verification**: Every paid request sends `X-Payment-Tx: <0x_base_tx_hash>`, verified directly against Base Mainnet RPC (`status === "0x1"`, USDC `Transfer` log to `0x6137ED1A93c8CFF1a6C3112A14bE04883f58E5F7`, and 600-second anti-replay block timestamp check).
- **Vercel Hobby-Tier Quota Protected**: Free `?demo=true` previews enforce `Cache-Control: public, s-maxage=60, stale-while-revalidate=120`; paid `X-Payment-Tx` calls bypass demo throttling and edge-cache upstream DexScreener/GoPlus responses for 15s (`s-maxage=15`).

---

## Aggressive Micro-Pricing (Base USDC)

| Endpoint | MCP Tool | Price (USDC) | Base Units | Engine |
| :--- | :--- | :---: | :---: | :--- |
| `POST /api/v1/calldata-firewall` | `audit_evm_calldata` | **$0.003** | `3000` | Deterministic EVM ABI & selector decoder (**0 external API calls**) |
| `POST /api/v1/swap-preflight` | `simulate_base_swap_preflight` | **$0.005** | `5000` | Direct Base RPC `eth_call` + `eth_getCode` pool depth & honeypot scan |
| `POST /api/v1/token-intel` | `scan_base_token_intel` | **$0.005** | `5000` | Edge-cached (15s) DexScreener + GoPlus Security aggregator |
| `GET /api/v1/health` | ??| **Free** | `0` | Live Base RPC latency, uptime, pricing & quota optimization status |

- **Live Deployment**: `https://baseguard-402.vercel.app`
- **Remote MCP Endpoint**: `https://baseguard-402.vercel.app/mcp`
- **x402 Pay-To Wallet (Base USDC)**: `0x6137ED1A93c8CFF1a6C3112A14bE04883f58E5F7`
- **Base USDC Asset**: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`

---

## 10-Second Copy-Paste Integrations

### 1. Claude Desktop / Cursor / Windsurf (Remote MCP)

Add to your MCP config (`claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "baseguard-402": {
      "url": "https://baseguard-402.vercel.app/mcp"
    }
  }
}
```

### 2. Coinbase AgentKit Pre-Swap Hook (`examples/coinbase_agentkit_guard.ts`)

```ts
import { assertSafeBaseTrade } from "./examples/coinbase_agentkit_guard";

// Screen calldata ($0.003 USDC) & token preflight ($0.005 USDC) before signing
await assertSafeBaseTrade({
  calldata: tx.data,
  to: tx.to,
  tokenAddress: targetToken,
  tradeAmountUsd: 1500,
  wallet: agentKitWallet // auto-pays x402 challenge in Base USDC
});
```

### 3. ElizaOS / ai16z Trading Agent Plugin (`examples/elizaos_guard_action.ts`)

```ts
import { baseGuardElizaPlugin } from "./examples/elizaos_guard_action";

const character = {
  name: "BaseAlphaBot",
  plugins: [baseGuardElizaPlugin]
};
```

### 4. LangChain / AutoGPT Python Wrapper (`examples/langchain_x402_tool.py`)

```python
from examples.langchain_x402_tool import baseguard_x402_request

verdict = baseguard_x402_request(
    "/api/v1/calldata-firewall",
    {"calldata": "0x095ea7b3000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
    demo=True,  # Pass pay_usdc_fn=... in production
)
print(verdict["verdict"])  # -> {"action": "BLOCK", "severity": "CRITICAL", "riskScore": 80}
```

---

## Instant CLI Verification (Zero Cost)

```bash
# Test against live Vercel deployment
BASE_URL="https://baseguard-402.vercel.app" node test_x402.mjs
```

### Quick `curl` Demo (Catches Unlimited `approve(MAX_UINT256)` Drainer)

```bash
curl -s "https://baseguard-402.vercel.app/api/v1/calldata-firewall?demo=true"
```

---

## Discovery Manifests (CORS `*`)

- `/.well-known/x402.json` ??Machine-readable x402 payment & endpoint spec
- `/.well-known/mcp.json` ??Remote MCP capability manifest
- `/llms.txt` ??LLM-optimized agent directory summary
- `/openapi.json` ??OpenAPI 3.1 specification

---

## License

MIT ??see [LICENSE](LICENSE). Maintained by [`meer9374-a11y`](https://github.com/meer9374-a11y).
