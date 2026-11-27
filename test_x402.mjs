/**
 * Zero-cost CLI verification suite for BaseGuard-402.
 * Verifies:
 *  1. /api/v1/health live Base RPC telemetry
 *  2. HTTP 402 x402 Payment Required responses on all 3 endpoints
 *  3. Deterministic calldata firewall catching approve(MAX_UINT256) drainer via ?demo=true
 *  4. MCP JSON-RPC 2.0 (initialize, tools/list, tools/call)
 *  5. Live Base tx hash verification guard (invalid/expired tx rejected cleanly with 402)
 *
 * Usage:
 *   BASE_URL="https://your-deployment.vercel.app" node test_x402.mjs
 *   (or run locally without BASE_URL to test against the configured production URL)
 */

const BASE_URL = (process.env.BASE_URL || "https://baseguard-402.vercel.app").replace(/\/$/, "");

const MALICIOUS_APPROVE_MAX =
  "0x095ea7b3" +
  "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" +
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

const EXPECTED_PAY_TO = "0x6137ED1A93c8CFF1a6C3112A14bE04883f58E5F7";
const EXPECTED_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

let passed = 0;
let failed = 0;

function assert(condition, label, detail = "") {
  if (condition) {
    console.log(`  [PASS] ${label}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${label}${detail ? ` -> ${detail}` : ""}`);
    failed++;
  }
}

async function run() {
  if (BASE_URL.includes("https://baseguard-402.vercel.app")) {
    console.error("Set BASE_URL env var to your live Vercel URL (e.g. BASE_URL=https://baseguard-402.vercel.app node test_x402.mjs)");
    process.exit(1);
  }

  console.log(`\n=== BaseGuard-402 Verification Suite ===`);
  console.log(`Target: ${BASE_URL}\n`);

  // 1. Health check
  console.log("1. Checking /api/v1/health ...");
  const healthRes = await fetch(`${BASE_URL}/api/v1/health`);
  const healthJson = await healthRes.json();
  assert(healthRes.status === 200, "Health endpoint returns 200");
  assert(healthJson.network?.payTo === EXPECTED_PAY_TO, "Health payTo matches wallet");
  assert(healthJson.network?.rpc?.ok === true, "Base Mainnet RPC connected", JSON.stringify(healthJson.network?.rpc));
  console.log(`     RPC: ${healthJson.network?.rpc?.rpcUrl} | Block: ${healthJson.network?.rpc?.blockNumber} | Latency: ${healthJson.network?.rpc?.latencyMs}ms`);

  // 2. HTTP 402 Payment Required verification across all 3 endpoints
  console.log("\n2. Checking x402 HTTP 402 challenges ...");
  const endpoints = [
    { path: "/api/v1/calldata-firewall", expectedAmount: "3000" },
    { path: "/api/v1/swap-preflight", expectedAmount: "5000" },
    { path: "/api/v1/token-intel", expectedAmount: "5000" }
  ];

  for (const ep of endpoints) {
    const res = await fetch(`${BASE_URL}${ep.path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    const body = await res.json();
    assert(res.status === 402, `${ep.path} returns HTTP 402`);
    assert(body.payTo === EXPECTED_PAY_TO, `${ep.path} payTo correct`);
    assert(body.asset === EXPECTED_USDC, `${ep.path} asset is Base USDC`);
    assert(body.amount === ep.expectedAmount, `${ep.path} amount is ${ep.expectedAmount} base units`, `got ${body.amount}`);
  }

  // 3. Calldata firewall decoding approve(MAX_UINT256)
  console.log("\n3. Checking /api/v1/calldata-firewall?demo=true on approve(MAX_UINT256) ...");
  const fwRes = await fetch(`${BASE_URL}/api/v1/calldata-firewall?demo=true`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      calldata: MALICIOUS_APPROVE_MAX,
      to: EXPECTED_USDC
    })
  });
  const fwJson = await fwRes.json();
  assert(fwRes.status === 200, "Demo calldata firewall returns 200");
  assert(fwJson.verdict?.action === "BLOCK", "Verdict action is BLOCK", `got ${fwJson.verdict?.action}`);
  assert(fwJson.verdict?.severity === "CRITICAL", "Verdict severity is CRITICAL");
  assert(fwJson.decoded?.functionName === "approve", "Decoded selector as approve()");
  assert(fwJson.decoded?.params?.isUnlimited === true, "Flagged MAX_UINT256 unlimited approval");
  assert((fwRes.headers.get("cache-control") || "").includes("s-maxage=60"), "Demo enforces Vercel edge caching (s-maxage=60)");

  console.log("\n--- Live Calldata Firewall Proof JSON ---");
  console.log(JSON.stringify(fwJson, null, 2));
  console.log("-----------------------------------------\n");

  // 4. Remote MCP JSON-RPC 2.0 (initialize, tools/list, tools/call)
  console.log("4. Checking /mcp JSON-RPC 2.0 ...");
  const initRes = await fetch(`${BASE_URL}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })
  });
  const initJson = await initRes.json();
  assert(initRes.status === 200 && initJson.result?.protocolVersion === "2024-11-05", "MCP initialize returns 2024-11-05");

  const listRes = await fetch(`${BASE_URL}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })
  });
  const listJson = await listRes.json();
  const toolNames = (listJson.result?.tools || []).map((t) => t.name);
  assert(toolNames.includes("audit_evm_calldata"), "MCP exposes audit_evm_calldata");
  assert(toolNames.includes("simulate_base_swap_preflight"), "MCP exposes simulate_base_swap_preflight");
  assert(toolNames.includes("scan_base_token_intel"), "MCP exposes scan_base_token_intel");

  const callRes = await fetch(`${BASE_URL}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "audit_evm_calldata",
        arguments: { calldata: MALICIOUS_APPROVE_MAX, demo: true }
      }
    })
  });
  const callJson = await callRes.json();
  const parsedToolOut = JSON.parse(callJson.result?.content?.[0]?.text || "{}");
  assert(parsedToolOut.verdict?.action === "BLOCK", "MCP tools/call blocks malicious approve(MAX_UINT256)");

  // 5. Live Base tx hash verification simulation (fake hash rejected cleanly on-chain)
  console.log("\n5. Checking live Base RPC X-Payment-Tx rejection on bogus hash ...");
  const fakeTx = "0x" + "1".repeat(64);
  const txRes = await fetch(`${BASE_URL}/api/v1/calldata-firewall`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Payment-Tx": fakeTx
    },
    body: JSON.stringify({ calldata: MALICIOUS_APPROVE_MAX })
  });
  const txJson = await txRes.json();
  assert(txRes.status === 402, "Bogus X-Payment-Tx rejected with HTTP 402");
  assert(txJson.paymentVerificationError?.code === "TX_NOT_FOUND", "Live Base RPC confirmed TX_NOT_FOUND", JSON.stringify(txJson.paymentVerificationError));

  // 6. Discovery manifests
  console.log("\n6. Checking discovery manifests ...");
  for (const path of ["/.well-known/x402.json", "/.well-known/mcp.json", "/llms.txt", "/openapi.json"]) {
    const r = await fetch(`${BASE_URL}${path}`);
    assert(r.status === 200, `${path} returns 200`);
  }

  console.log(`\n=== Summary: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("Test suite error:", err);
  process.exit(1);
});
