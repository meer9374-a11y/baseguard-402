"""
BaseGuard-402 x402 Payment Wrapper for LangChain / AutoGPT / CrewAI Python Agents
Zero external dependencies required (uses Python stdlib urllib, or drop into langchain.tools).
"""

import json
import urllib.request
import urllib.error
from typing import Callable, Optional, Dict, Any

BASEGUARD_URL = "https://baseguard-402.vercel.app"


def baseguard_x402_request(
    endpoint: str,
    payload: Dict[str, Any],
    pay_usdc_fn: Optional[Callable[[str, str, str], str]] = None,
    demo: bool = False,
) -> Dict[str, Any]:
    """
    Calls a BaseGuard-402 endpoint with automatic x402 payment handling.

    Args:
        endpoint: e.g. "/api/v1/calldata-firewall", "/api/v1/swap-preflight", "/api/v1/token-intel"
        payload: JSON request body
        pay_usdc_fn: Callback(pay_to, amount_base_units, usdc_asset) -> base_tx_hash
        demo: Set True to use free edge-cached preview (?demo=true)
    """
    url = f"{BASEGUARD_URL}{endpoint}{'?demo=true' if demo else ''}"
    body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        if err.code != 402:
            raise RuntimeError(f"BaseGuard-402 HTTP {err.code}: {err.read().decode('utf-8')}")

        challenge = json.loads(err.read().decode("utf-8"))
        if not pay_usdc_fn:
            return {"status": 402, "payment_required": challenge}

        # Stream micro-USDC payment ($0.003 - $0.005) on Base L2
        tx_hash = pay_usdc_fn(challenge["payTo"], challenge["amount"], challenge["asset"])

        # Retry with stateless on-chain payment proof
        paid_req = urllib.request.Request(
            f"{BASEGUARD_URL}{endpoint}",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Payment-Tx": tx_hash,
            },
            method="POST",
        )
        with urllib.request.urlopen(paid_req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))


def audit_calldata_tool(calldata: str, to: str = "", demo: bool = True) -> str:
    """LangChain-compatible tool function to screen EVM calldata before signing."""
    result = baseguard_x402_request(
        "/api/v1/calldata-firewall",
        {"calldata": calldata, "to": to or None},
        demo=demo,
    )
    return json.dumps(result, indent=2)


if __name__ == "__main__":
    # Quick smoke test catching an unlimited approve(MAX_UINT256) drainer payload
    malicious_approve = (
        "0x095ea7b3"
        "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    print(audit_calldata_tool(malicious_approve, demo=True))
