"""HTTP client for Hacash Agent Pay Protocol (HAP) v1."""

from __future__ import annotations

import time
import uuid
from typing import Any, Optional
from urllib.parse import urlsplit

import requests

from .close import assert_ready_for_close, build_close_intent, close_checklist
from .crypto import HacashKey


class AgentPayError(Exception):
    def __init__(self, code: str, message: str, envelope: Optional[dict] = None):
        super().__init__(message)
        self.code = code
        self.envelope = envelope


class AgentPayClient:
    """
    Primary API for AI agents.

        key = HacashKey.from_password("secret")
        c = AgentPayClient("http://127.0.0.1:9090", agent_id="bot")
        c.drain_inbox(key)
        env = c.pay(from_addr=key.address, to="1…", amount_hac="1:247",
                    idempotency_key="inv-1")
    """

    def __init__(
        self,
        base_url: str,
        agent_id: str = "agent",
        timeout: float = 30.0,
        wait_timeout_s: float = 120.0,
        poll_s: float = 1.5,
        session: Optional[requests.Session] = None,
        api_key: str = "",
        agent_api_key: str = "",
    ):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.timeout = timeout
        self.wait_timeout_s = wait_timeout_s
        self.poll_s = poll_s
        self.session = session or requests.Session()
        # Prefer agent_api_key; falls back to api_key (X-Api-Token / Bearer)
        self.api_key = (agent_api_key or api_key or "").strip()

    def manifest(self) -> dict:
        return self._get("/v1/agent/v1/manifest")

    def tools(self) -> dict:
        return self._get("/v1/agent/v1/tools")

    def quote(
        self,
        from_addr: str,
        to: str,
        amount_hac: str = "",
        amount_satoshi: int = 0,
        local_only: bool = False,
    ) -> dict:
        body = self._post(
            "/v1/agent/v1/quote",
            {
                "from": from_addr,
                "to": to,
                "amount_hac": amount_hac,
                "amount_satoshi": amount_satoshi,
                "local_only": local_only,
            },
        )
        if not body.get("ok"):
            raise AgentPayError("quote_failed", str(body))
        return body["quote"]

    def pay(
        self,
        from_addr: str,
        to: str,
        idempotency_key: str,
        amount_hac: str = "",
        amount_satoshi: int = 0,
        local_only: bool = False,
        meta: Optional[dict] = None,
        intent: Optional[dict] = None,
    ) -> dict:
        m = {"agent_id": self.agent_id, **(meta or {})}
        env = self._post(
            "/v1/agent/v1/pay",
            {
                "from": from_addr,
                "to": to,
                "amount_hac": amount_hac,
                "amount_satoshi": amount_satoshi,
                "idempotency_key": idempotency_key,
                "local_only": local_only,
                "meta": m,
                "intent": intent or {},
            },
        )
        if not env.get("ok"):
            err = env.get("error") or {}
            raise AgentPayError(err.get("code", "pay_failed"), err.get("message", str(env)), env)
        return env

    def status(self, payment_id: str) -> dict:
        env = self._get(f"/v1/agent/v1/payment/{payment_id}")
        if not env.get("ok") and env.get("error"):
            e = env["error"]
            raise AgentPayError(e.get("code", "error"), e.get("message", ""), env)
        return env

    def sign(
        self,
        payment_id: str,
        address: str,
        signature_hex: str,
        public_key_hex: str = "",
    ) -> dict:
        env = self._post(
            "/v1/agent/v1/sign",
            {
                "payment_id": payment_id,
                "address": address,
                "signature_hex": signature_hex,
                "public_key_hex": public_key_hex,
                "agent_id": self.agent_id,
            },
        )
        if not env.get("ok"):
            err = env.get("error") or {}
            raise AgentPayError(err.get("code", "sign_failed"), err.get("message", str(env)), env)
        return env

    def inbox(self, address: str) -> list:
        body = self._get(f"/v1/agent/v1/inbox?address={address}")
        if not body.get("ok"):
            raise AgentPayError("inbox_failed", str(body))
        return body.get("inbox") or []

    def receipt(self, payment_id: str) -> dict:
        body = self._get(f"/v1/agent/v1/receipt/{payment_id}")
        if not body.get("ok"):
            raise AgentPayError("no_receipt", body.get("err", "no receipt"))
        return body["receipt"]

    def create_invoice(
        self,
        payee: str,
        amount_hac: str,
        payer_hint: str = "",
        description: str = "",
        ttl_secs: int = 3600,
        callback_url: str = "",
        meta: Optional[dict] = None,
    ) -> dict:
        """Request-to-pay: create invoice (you are payee)."""
        body = self._post(
            "/v1/agent/v1/invoice",
            {
                "payee": payee,
                "amount_hac": amount_hac,
                "payer_hint": payer_hint,
                "description": description,
                "ttl_secs": ttl_secs,
                "callback_url": callback_url,
                "meta": {"agent_id": self.agent_id, **(meta or {})},
            },
        )
        if not body.get("ok"):
            raise AgentPayError("invoice_failed", body.get("err", str(body)))
        return body["invoice"]

    def get_invoice(self, invoice_id: str) -> dict:
        body = self._get(f"/v1/agent/v1/invoice/{invoice_id}")
        if not body.get("ok"):
            raise AgentPayError("not_found", body.get("err", "not found"))
        return body["invoice"]

    def list_invoices(self, address: str, limit: int = 50) -> list:
        body = self._get(f"/v1/agent/v1/invoices?address={address}&limit={limit}")
        return body.get("invoices") or []

    def pay_invoice(
        self,
        invoice_id: str,
        from_addr: str,
        idempotency_key: Optional[str] = None,
        key: Optional[HacashKey] = None,
        local_only: bool = False,
    ) -> dict:
        """Fulfill request-to-pay; optional auto-sign as payer."""
        idem = idempotency_key or f"invpay-{uuid.uuid4()}"
        env = self._post(
            "/v1/agent/v1/pay-invoice",
            {
                "invoice_id": invoice_id,
                "from": from_addr,
                "idempotency_key": idem,
                "local_only": local_only,
                "meta": {"agent_id": self.agent_id},
            },
        )
        if not env.get("ok"):
            err = env.get("error") or {}
            raise AgentPayError(err.get("code", "pay_failed"), err.get("message", str(env)), env)
        pid = _payment_id(env)
        if key and pid:
            env = self.sign_if_needed(key, env)
            env = self.wait_until_done(pid, key)
        receipt = None
        if env.get("machine", {}).get("done") and env.get("machine", {}).get("success") and pid:
            try:
                receipt = self.receipt(pid)
            except AgentPayError:
                pass
        return {"envelope": env, "receipt": receipt, "payment_id": pid, "invoice_id": invoice_id}

    def cancel_payment(self, payment_id: str, by_address: str) -> dict:
        return self._post(
            f"/v1/agent/v1/payment/{payment_id}/cancel",
            {"by_address": by_address},
        )

    def policy(self) -> dict:
        return self._get("/v1/agent/v1/policy")

    def ledger(self) -> dict:
        return self._get("/v1/agent/v1/ledger")

    # --- Identity ---

    def register_identity(
        self, agent_id: str, public_key_hex: str, label: str = "", contact: str = ""
    ) -> dict:
        body = self._post(
            "/v1/agent/v1/identity/register",
            {
                "agent_id": agent_id,
                "public_key_hex": public_key_hex,
                "label": label,
                "contact": contact,
            },
        )
        if not body.get("ok"):
            raise AgentPayError("identity_failed", body.get("err", str(body)))
        return body["identity"]

    def identity_challenge(self, agent_id: str) -> dict:
        body = self._get(f"/v1/agent/v1/identity/challenge?agent_id={agent_id}")
        if not body.get("ok"):
            raise AgentPayError("challenge_failed", body.get("err", str(body)))
        return body["challenge"]

    def verify_identity(
        self, agent_id: str, challenge_id: str, signature_hex: str, public_key_hex: str = ""
    ) -> dict:
        body = self._post(
            "/v1/agent/v1/identity/verify",
            {
                "agent_id": agent_id,
                "challenge_id": challenge_id,
                "signature_hex": signature_hex,
                "public_key_hex": public_key_hex,
            },
        )
        if not body.get("ok"):
            raise AgentPayError("verify_failed", body.get("err", str(body)))
        return body["identity"]

    def prove_identity(self, key: HacashKey, agent_id: Optional[str] = None) -> dict:
        """Register + challenge + verify in one shot using local key."""
        aid = agent_id or self.agent_id
        pk = key.public_key.hex()
        self.register_identity(aid, pk)
        ch = self.identity_challenge(aid)
        sig = key.sign_hash_hex(ch["message_hash_hex"])
        return self.verify_identity(aid, ch["challenge_id"], sig, pk)

    # --- Micropayments ---

    def micro_open(
        self,
        payer: str,
        payee: str,
        max_satoshi: int = 0,
        max_hac_mei: int = 0,
        create_payments: bool = False,
        local_only: bool = True,
    ) -> dict:
        body = self._post(
            "/v1/agent/v1/micro/open",
            {
                "payer": payer,
                "payee": payee,
                "max_satoshi": max_satoshi,
                "max_hac_mei": max_hac_mei,
                "create_payments": create_payments,
                "local_only": local_only,
                "agent_id": self.agent_id,
            },
        )
        if not body.get("ok"):
            raise AgentPayError("micro_open_failed", body.get("err", str(body)))
        return body["stream"]

    def micro_push(
        self,
        stream_id: str,
        key: HacashKey,
        amount_satoshi: int = 0,
        amount_mei: int = 0,
        amount_hac: str = "",
        note: str = "",
        idempotency_key: str = "",
    ) -> dict:
        """Push micro; auto-signs commit when hub returns signature_required."""
        payload = {
            "stream_id": stream_id,
            "amount_satoshi": amount_satoshi,
            "amount_mei": amount_mei,
            "amount_hac": amount_hac,
            "note": note,
            "idempotency_key": idempotency_key,
            "signature_hex": "",
        }
        body = self._post("/v1/agent/v1/micro/push", payload)
        if body.get("err") == "signature_required" and body.get("action_required"):
            ar = body["action_required"]
            sig = key.sign_hash_hex(ar["sign_this_hash_hex"])
            payload["signature_hex"] = sig
            body = self._post("/v1/agent/v1/micro/push", payload)
        if not body.get("ok"):
            raise AgentPayError("micro_push_failed", body.get("err", str(body)), body)
        return body

    def micro_close(self, stream_id: str, by_address: str) -> dict:
        body = self._post(
            f"/v1/agent/v1/micro/{stream_id}/close",
            {"by_address": by_address},
        )
        if not body.get("ok"):
            raise AgentPayError("micro_close_failed", body.get("err", str(body)))
        return body["stream"]

    def normalize_amount(
        self,
        amount_hac: str = "",
        amount_satoshi: int = 0,
        amount_mei: int = 0,
        satoshi: int = 0,
    ) -> dict:
        return self._post(
            "/v1/agent/v1/amounts/normalize",
            {
                "amount_hac": amount_hac,
                "amount_satoshi": amount_satoshi,
                "amount_mei": amount_mei,
                "satoshi": satoshi,
            },
        )

    def drain_inbox(self, key: HacashKey) -> int:
        """Sign trusted local incoming-payment items. Returns count signed.

        Outbound and intermediary signatures require explicit application approval.
        """
        n = 0
        for item in self.inbox(key.address):
            action = item.get("action") or {}
            if action.get("address") != key.address:
                continue
            if item.get("role") != "payee":
                continue
            endpoint = (action.get("sign_endpoint") or "").strip()
            if (
                item.get("kind") == "sign_on_origin_hub"
                or not self._is_local_sign_endpoint(endpoint)
            ):
                continue
            sig = key.sign_hash_hex(item["sign_this_hash_hex"])
            self.sign(item["payment_id"], key.address, sig)
            n += 1
        return n

    def sign_if_needed(self, key: HacashKey, env: dict) -> dict:
        ar = env.get("action_required")
        if not ar:
            return env
        kind = ar.get("kind") or ""
        # Only sign when it is our turn
        if kind != "sign_payment":
            return env
        if ar.get("address") != key.address:
            return env
        endpoint = (ar.get("sign_endpoint") or "").strip()
        if not self._is_local_sign_endpoint(endpoint):
            return env
        sig = key.sign_hash_hex(ar["sign_this_hash_hex"])
        return self.sign(str(ar["payment_id"]), key.address, sig)

    def _is_local_sign_endpoint(self, endpoint: str) -> bool:
        try:
            actual = urlsplit(endpoint)
            expected = urlsplit(f"{self.base_url}/v1/agent/v1/sign")
            return (
                actual.scheme.lower() == expected.scheme.lower()
                and actual.netloc.lower() == expected.netloc.lower()
                and actual.path == expected.path
                and not actual.query
                and not actual.fragment
                and actual.username is None
                and actual.password is None
            )
        except (TypeError, ValueError):
            return False

    def _sign_at_endpoint(
        self,
        sign_endpoint: str,
        payment_id: str,
        address: str,
        signature_hex: str,
        public_key_hex: str = "",
    ) -> dict:
        """POST sign to an absolute origin hub URL (foreign multi-hop)."""
        if not self._is_local_sign_endpoint(sign_endpoint):
            raise AgentPayError(
                "unsafe_sign_endpoint", "refusing to send a signature or API key to a foreign origin"
            )
        url = sign_endpoint.strip()
        body = {
            "payment_id": payment_id,
            "address": address,
            "signature_hex": signature_hex,
            "public_key_hex": public_key_hex,
            "agent_id": self.agent_id,
        }
        r = self.session.post(
            url, json=body, timeout=self.timeout, headers=self._auth_headers()
        )
        try:
            env = r.json()
        except Exception:
            r.raise_for_status()
            raise
        if not env.get("ok"):
            err = env.get("error") or {}
            raise AgentPayError(
                err.get("code", "sign_failed"),
                err.get("message", str(env)),
                env,
            )
        return env

    def wait_until_done(self, payment_id: str, key: Optional[HacashKey] = None) -> dict:
        start = time.time()
        env = self.status(payment_id)
        while not env.get("machine", {}).get("done"):
            if time.time() - start > self.wait_timeout_s:
                raise AgentPayError("timeout", f"payment {payment_id} not done", env)
            if key:
                env = self.sign_if_needed(key, env)
                if env.get("machine", {}).get("done"):
                    break
                self.drain_inbox(key)
                env = self.status(payment_id)
                if env.get("machine", {}).get("done"):
                    break
            sleep = (env.get("machine") or {}).get("next_poll_ms", self.poll_s * 1000) / 1000.0
            time.sleep(max(sleep, 0.2))
            env = self.status(payment_id)
        return env

    def send(
        self,
        from_addr: str,
        to: str,
        amount_hac: str,
        idempotency_key: Optional[str] = None,
        key: Optional[HacashKey] = None,
        local_only: bool = False,
        meta: Optional[dict] = None,
    ) -> dict:
        """Quote → pay → optional auto-sign/wait. Returns {envelope, receipt?, payment_id}."""
        q = self.quote(from_addr, to, amount_hac=amount_hac, local_only=local_only)
        if not q.get("can_pay"):
            raise AgentPayError("no_route", q.get("note", "no route"))
        idem = idempotency_key or f"send-{uuid.uuid4()}"
        env = self.pay(
            from_addr,
            to,
            idem,
            amount_hac=amount_hac,
            local_only=local_only,
            meta=meta,
        )
        pid = _payment_id(env)
        if key and pid:
            env = self.sign_if_needed(key, env)
            env = self.wait_until_done(pid, key)
        receipt = None
        if env.get("machine", {}).get("done") and env.get("machine", {}).get("success") and pid:
            try:
                receipt = self.receipt(pid)
            except AgentPayError:
                pass
        return {"envelope": env, "receipt": receipt, "payment_id": pid}

    # --- L1 ChannelClose helpers (evidence + submit relay; no key custody) ---

    def close_plan(self, channel_id: str) -> dict:
        """GET agent close-plan (ready flag, distribution, wallet_actions)."""
        body = self._get(f"/v1/agent/v1/close-plan/{channel_id}")
        if not body.get("ok"):
            err = body.get("error") or {}
            raise AgentPayError(
                err.get("code", "close_plan_failed"),
                err.get("message", body.get("err", str(body))),
                body,
            )
        return body

    def export_dispute(self, channel_id: str) -> dict:
        """Raw hub dispute export (same evidence as close-plan.export)."""
        body = self._get(f"/v1/channels/{channel_id}/dispute")
        if not body.get("ok"):
            raise AgentPayError("dispute_export_failed", body.get("err", str(body)))
        return body.get("export") or body

    def close_intent(self, channel_id: str) -> dict:
        """Normalized close intent (hacash-l2-close-intent/1) for agents."""
        try:
            body = self.close_plan(channel_id)
            return build_close_intent(body)
        except AgentPayError:
            export = self.export_dispute(channel_id)
            return build_close_intent({"export": export})

    def close_checklist_for(self, channel_id: str) -> list:
        return close_checklist(self.close_intent(channel_id))

    def require_ready_for_close(self, channel_id: str) -> dict:
        """Return close intent or raise if not ready for L1 close."""
        intent = self.close_intent(channel_id)
        assert_ready_for_close(intent)
        return intent

    def submit_signed_l1_tx(self, tx_hex: str, path: str = "") -> dict:
        """
        Relay an already-signed L1 tx hex to fullnode via hub.
        Requires hub api_token / agent_api_key. Does not build ChannelClose.
        """
        body = self._post(
            "/v1/l1/submit",
            {"tx_hex": tx_hex, "path": path},
        )
        if not body.get("ok"):
            raise AgentPayError("l1_submit_failed", body.get("err", str(body)))
        return body

    def _auth_headers(self) -> dict:
        if not self.api_key:
            return {}
        return {
            "X-Api-Token": self.api_key,
            "Authorization": f"Bearer {self.api_key}",
        }

    def _get(self, path: str) -> dict:
        r = self.session.get(
            self.base_url + path, timeout=self.timeout, headers=self._auth_headers()
        )
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, body: Any) -> dict:
        r = self.session.post(
            self.base_url + path,
            json=body,
            timeout=self.timeout,
            headers=self._auth_headers(),
        )
        # HAP returns 400 with envelope JSON — still parse
        try:
            return r.json()
        except Exception:
            r.raise_for_status()
            raise


def _payment_id(env: dict) -> str:
    ar = env.get("action_required") or {}
    if ar.get("payment_id"):
        return str(ar["payment_id"])
    res = env.get("result") or {}
    if res.get("payment_id"):
        return str(res["payment_id"])
    pay = res.get("payment") or {}
    if isinstance(pay, dict) and pay.get("payment_id"):
        return str(pay["payment_id"])
    return ""
