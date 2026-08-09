# hacash-agent-pay (Python)

AI agent SDK for **Hacash Agent Pay** (L2 Channel Chain hub).

```bash
cd sdk/python
pip install -e .
```

```python
from hacash_agent_pay import AgentPayClient, HacashKey

key = HacashKey.from_password("my-agent-secret")
client = AgentPayClient("http://127.0.0.1:9090", agent_id="bot-1")

# Work queue — sign anything waiting for us
client.drain_inbox(key)

# Send (auto-sign when it's our turn as payer; payee must drain too)
out = client.send(
    from_addr=key.address,
    to="1PayeeAddress…",
    amount_hac="1:247",
    key=key,
    meta={"purpose": "api_fee", "skill": "search"},
)
print(out["receipt"]["receipt_hash_hex"] if out["receipt"] else out["envelope"]["machine"])
```

See root [AGENT-PAYMENTS.md](../../AGENT-PAYMENTS.md).
