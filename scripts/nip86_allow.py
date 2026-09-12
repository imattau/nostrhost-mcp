"""NIP-86 helper: allowlist a pubkey on the local control relay (admin-only)."""
import base64
import hashlib
import json

import urllib.request

NIP86_URL = "http://127.0.0.1:4848/"
RELAY_WS = "ws://127.0.0.1:4848"
KIND_NIP86 = 24133


def _sign(sk, pk, kind, content, tags):
    import time
    from coincurve import PrivateKey

    created_at = int(time.time())
    serialized = json.dumps([0, pk, created_at, kind, tags, content], separators=(",", ":"), ensure_ascii=False).encode()
    event_id = hashlib.sha256(serialized).hexdigest()
    sig = PrivateKey(bytes.fromhex(sk)).sign_schnorr(bytes.fromhex(event_id)).hex()
    return {"id": event_id, "pubkey": pk, "created_at": created_at, "kind": kind, "tags": tags, "content": content, "sig": sig}


def allow_pubkey(admin_sk: str, admin_pk: str, pubkey: str, reason: str) -> str:
    body = json.dumps({"method": "allowpubkey", "params": [pubkey, reason]}, separators=(",", ":")).encode()
    content = base64.b64encode(body).decode()
    payload_hash = hashlib.sha256(body).hexdigest()
    tags = [["u", RELAY_WS], ["method", "allowpubkey"], ["payload", payload_hash]]
    event = _sign(admin_sk, admin_pk, KIND_NIP86, content, tags)
    req = urllib.request.Request(
        NIP86_URL,
        data=body,
        headers={
            "Content-Type": "application/nostr+json+rpc",
            "Authorization": "Nostr " + base64.b64encode(json.dumps(event).encode()).decode(),
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode()


def operator_keys():
    import tomllib
    from coincurve import PublicKeyXOnly

    conf = tomllib.load(open("/etc/nostrhost/operator.toml", "rb"))
    sk = conf["operator_sk"]
    pk = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    return sk, pk


if __name__ == "__main__":
    import sys

    pk = sys.argv[1]
    sk, op_pk = operator_keys()
    print("allowing", pk[:16], "as admin on relay...")
    print("response:", allow_pubkey(sk, op_pk, pk, "phase4 non-owner admin"))
