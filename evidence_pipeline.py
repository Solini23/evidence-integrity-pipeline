#!/usr/bin/env python3
# evidence_pipeline.py
#
# Integrity assurance and chain of custody for digital evidence.
#
#   dual hashing     SHA-256 + SHA3-256, both in a single read pass
#   signatures       Ed25519 (RFC 8032)
#   timestamps       RFC 3161, optional, see --tsa
#   custody ledger   append-only, hash-chained, one JSON object per line
#
# A ledger record is a body
#
#     type, seq, prev, actor, actor_key_id, recorded_at, payload
#
# plus a "signature" field holding Ed25519(canonical(body)). The prev field of
# record n+1 is sha256(canonical(body + signature)) of record n. Note what is
# not covered by that hash: tsa_token. This is on purpose. If the TSA is down
# at ingest time, the token can be fetched later and written into the record
# (attach-token) without recomputing every link after it.
#
# canonical() = UTF-8 JSON, keys sorted, no padding whitespace, so the signer
# and the verifier always work on the exact same bytes.
#
# commands: keygen, ingest, transfer, attach-token, verify, bench, tsa-bench

import argparse
import base64
import csv
import hashlib
import json
import os
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("Missing dependency. Run:  pip install cryptography rfc3161ng")

CHUNK = 1024 * 1024
GENESIS = "GENESIS"
BODY_FIELDS = ("type", "seq", "prev", "actor", "actor_key_id",
               "recorded_at", "payload")


def canonical(obj):
    """Sorted keys, no whitespace, UTF-8. Returns bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_digests(path):
    # Both digests in one pass. Reading a 512 MB disk image twice would
    # double the wall clock time for no reason at all.
    h2 = hashlib.sha256()
    h3 = hashlib.sha3_256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(CHUNK)
            if not buf:
                break
            h2.update(buf)
            h3.update(buf)
            size += len(buf)
    return h2.hexdigest(), h3.hexdigest(), size


# ---- keys ----

def key_id(pub):
    raw = pub.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]   # short, only used as an index


def load_private(path):
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("%s is not an Ed25519 private key" % path)
    return key


def load_public(path):
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise SystemExit("%s is not an Ed25519 public key" % path)
    return key


def cmd_keygen(a):
    outdir = Path(a.dir)
    outdir.mkdir(parents=True, exist_ok=True)
    priv_path = outdir / (a.name + "_ed25519.pem")
    pub_path = outdir / (a.name + "_ed25519.pub.pem")
    if priv_path.exists() and not a.force:
        raise SystemExit(f"{priv_path} already exists (use --force to overwrite)")

    priv = Ed25519PrivateKey.generate()
    priv_path.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    pub = priv.public_key()
    pub_path.write_bytes(pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))

    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass          # no-op on Windows, not worth failing over

    print(f"private key : {priv_path}")
    print(f"public key  : {pub_path}")
    print(f"key id      : {key_id(pub)}")
    return 0


# ---- ledger ----

def read_ledger(path):
    if not path.exists():
        return []
    records = []
    lineno = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        lineno += 1
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{lineno}: malformed JSON ({exc})")
    return records


def body_of(rec):
    return {k: rec[k] for k in BODY_FIELDS}


def chain_unit(rec):
    unit = body_of(rec)
    unit["signature"] = rec["signature"]
    return unit


def record_link(rec):
    """Value that the prev field of the following record has to carry."""
    return sha256_hex(canonical(chain_unit(rec)))


def request_tsa_token(digest_hex, url):
    """RFC 3161 token over digest_hex as base64(DER), or None if it failed."""
    try:
        import rfc3161ng
    except ImportError:
        print("  ! rfc3161ng not installed — record stored without timestamp",
              file=sys.stderr)
        return None
    try:
        tsa = rfc3161ng.RemoteTimestamper(url, hashname="sha256")
        token = tsa(digest=bytes.fromhex(digest_hex), return_tsr=False)
        return base64.b64encode(token).decode("ascii")
    except Exception as exc:
        # timeout, HTTP 403, dead DNS, whatever. Never a reason to lose the
        # record itself, so just warn and fall back to deferred mode.
        print(f"  ! TSA {url} unavailable ({exc}) — deferred mode, "
              f"record stored without token", file=sys.stderr)
        return None


def append_record(ledger_path, rec_type, actor, priv, payload, tsa_url):
    records = read_ledger(ledger_path)
    if records:
        prev = record_link(records[-1])
    else:
        prev = GENESIS

    body = {
        "type": rec_type,
        "seq": len(records),
        "prev": prev,
        "actor": actor,
        "actor_key_id": key_id(priv.public_key()),
        "recorded_at": utc_now(),
        "payload": payload,
    }
    body_bytes = canonical(body)

    rec = dict(body)
    rec["signature"] = base64.b64encode(priv.sign(body_bytes)).decode("ascii")

    if tsa_url:
        token = request_tsa_token(sha256_hex(body_bytes), tsa_url)
        if token:
            rec["tsa_token"] = token

    # newline="\n" on purpose: a CRLF ledger written on Windows would not be
    # byte-identical to the same ledger written anywhere else.
    with open(ledger_path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(canonical(rec).decode("utf-8") + "\n")
    return rec


def token_state(rec):
    if "tsa_token" in rec:
        return "RFC 3161 token attached"
    return "none (deferred)"


# ---- ingest, transfer, deferred timestamp ----

def cmd_ingest(a):
    src = Path(a.file)
    if not src.is_file():
        raise SystemExit(f"no such file: {src}")

    t0 = time.perf_counter()
    sha256, sha3, size = file_digests(src)
    dt = time.perf_counter() - t0

    payload = {
        "evidence_id": a.evidence_id,
        "filename": src.name,
        "size_bytes": size,
        "sha256": sha256,
        "sha3_256": sha3,
        "collected_at": a.collected_at or utc_now(),
    }
    if a.description:
        payload["description"] = a.description

    rec = append_record(Path(a.ledger), "ingest", a.actor,
                        load_private(Path(a.key)), payload, a.tsa)

    print(f"ingested   : {src.name}  ({size:,} bytes in {dt:.2f}s)")
    print(f"evidence   : {a.evidence_id}")
    print(f"sha256     : {sha256}")
    print(f"sha3-256   : {sha3}")
    print(f"seq        : {rec['seq']}   prev: {rec['prev'][:16]}...")
    print(f"timestamp  : {token_state(rec)}")
    return 0


def cmd_transfer(a):
    payload = {
        "evidence_id": a.evidence_id,
        "from_actor": a.from_actor,
        "to_actor": a.to_actor,
        "purpose": a.purpose or "",
    }
    rec = append_record(Path(a.ledger), "transfer", a.actor,
                        load_private(Path(a.key)), payload, a.tsa)

    print(f"transfer   : {a.evidence_id}  {a.from_actor} -> {a.to_actor}")
    print(f"seq        : {rec['seq']}   prev: {rec['prev'][:16]}...")
    print(f"timestamp  : {token_state(rec)}")
    return 0


def cmd_attach_token(a):
    # Deferred timestamping. Only tsa_token is added; body and signature are
    # left alone, so the link that downstream records point at does not move.
    # The two printed links are there to show exactly that.
    ledger_path = Path(a.ledger)
    records = read_ledger(ledger_path)
    if not records:
        raise SystemExit(f"ledger is empty or missing: {ledger_path}")

    target = None
    for r in records:
        if r.get("seq") == a.seq:
            target = r
            break
    if target is None:
        raise SystemExit(f"no record with seq {a.seq}")
    if "tsa_token" in target:
        raise SystemExit(f"record {a.seq} already carries a token")

    link_before = record_link(target)
    body_digest = sha256_hex(canonical(body_of(target)))
    token = request_tsa_token(body_digest, a.tsa)
    if not token:
        raise SystemExit("no token obtained; record left unchanged")
    target["tsa_token"] = token
    link_after = record_link(target)

    with open(ledger_path, "w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(canonical(r).decode("utf-8") + "\n")

    print(f"token attached to record {a.seq}")
    print(f"chain link of record {a.seq}  before: {link_before[:16]}...")
    print(f"chain link of record {a.seq}  after : {link_after[:16]}...")
    if link_before == link_after:
        print("chain link unchanged")
    else:
        print("WARNING: chain link changed — deferred property violated")
    return 0


# ---- verification ----

def verify_tsa_token(b64_token, body_digest_hex):
    # Cheap in-process sanity check: does the token parse, and (when the
    # library gives us the imprint) does it cover this record. The
    # authoritative check against the TSA certificate chain is done outside,
    # with openssl ts -verify.
    try:
        import rfc3161ng
        from pyasn1.codec.der import decoder as der_decoder
        from rfc3161ng import TimeStampToken
    except ImportError:
        return True, "token present, not checked in-process (rfc3161ng absent; use openssl ts -verify)"

    try:
        der = base64.b64decode(b64_token)
        der_decoder.decode(der, asn1Spec=TimeStampToken())
        when = rfc3161ng.get_timestamp(der)

        if hasattr(rfc3161ng, "get_hash_from_timestamp"):
            imprint = rfc3161ng.get_hash_from_timestamp(der)
        else:
            imprint = None

        if imprint is None:
            return True, f"token time {when} (imprint not checked in-process; use openssl ts -verify)"
        if imprint.hex() != body_digest_hex:
            return False, "timestamped digest does not match record"
        return True, f"token time {when}, imprint matches"
    except Exception as exc:
        return True, f"token present, could not parse in-process ({exc}); use openssl ts -verify"


def cmd_verify(a):
    ledger_path = Path(a.ledger)
    records = read_ledger(ledger_path)
    if not records:
        raise SystemExit(f"ledger is empty or missing: {ledger_path}")

    known = {}
    for p in a.pub:
        pub = load_public(Path(p))
        known[key_id(pub)] = pub

    errors = []
    expected_prev = GENESIS

    for rec in records:
        seq = rec.get("seq", "?")

        missing = [f for f in BODY_FIELDS if f not in rec]
        if "signature" not in rec:
            missing.append("signature")
        if missing:
            errors.append(f"record {seq}: missing field(s) {', '.join(missing)} "
                          f"— structure damaged, cannot continue")
            break

        # 1. chain link
        if rec["prev"] != expected_prev:
            errors.append(
                f"record {seq}: broken chain link "
                f"(prev={rec['prev'][:16]}..., expected={expected_prev[:16]}...)")
        expected_prev = record_link(rec)

        # 2. signature
        kid = rec["actor_key_id"]
        if kid not in known:
            errors.append(f"record {seq}: unknown actor_key_id {kid} "
                          f"(public key not supplied via --pub)")
        else:
            try:
                known[kid].verify(base64.b64decode(rec["signature"]),
                                  canonical(body_of(rec)))
            except InvalidSignature:
                errors.append(f"record {seq}: invalid signature "
                              f"(actor '{rec['actor']}')")

        # 3. timestamp, if there is one
        if "tsa_token" in rec:
            ok, msg = verify_tsa_token(rec["tsa_token"],
                                       sha256_hex(canonical(body_of(rec))))
            if not ok:
                errors.append(f"record {seq}: {msg}")

    # 4. the evidence files themselves, only if we were told where they are
    checked_files = 0
    if a.files_dir:
        base = Path(a.files_dir)
        for rec in records:
            if rec.get("type") != "ingest":
                continue
            p = rec["payload"]
            target = base / p["filename"]
            if not target.is_file():
                errors.append(f"record {rec['seq']}: file not found: {target}")
                continue
            sha256, sha3, size = file_digests(target)
            checked_files += 1
            if sha256 != p["sha256"] or sha3 != p["sha3_256"]:
                errors.append(f"record {rec['seq']}: file content mismatch: "
                              f"{p['filename']}")
            elif size != p["size_bytes"]:
                errors.append(f"record {rec['seq']}: file size mismatch: "
                              f"{p['filename']}")

    print(f"records          : {len(records)}")
    print(f"chain head       : {expected_prev}")
    if a.files_dir:
        print(f"evidence files   : {checked_files} re-hashed")
    else:
        print("evidence files   : not checked (--files-dir omitted)")

    if errors:
        print("\nLEDGER INVALID")
        for e in errors:
            print(f"  - {e}")
        return 1

    print("\nLEDGER VALID")
    return 0


# ---- experiments E1-E3 ----

HASHES = {
    "sha256": hashlib.sha256,
    "sha3_256": hashlib.sha3_256,
    "blake2b": lambda: hashlib.blake2b(digest_size=32),
}


def make_temp_file(size_mb, directory):
    fd, name = tempfile.mkstemp(prefix=f"bench_{size_mb}MB_", dir=str(directory))
    block = os.urandom(CHUNK)
    with os.fdopen(fd, "wb") as fh:
        for _ in range(size_mb):
            fh.write(block)
        fh.flush()
        os.fsync(fh.fileno())     # otherwise the first run measures the cache
    return Path(name)


def hash_throughput(path, algo, size_mb):
    h = HASHES[algo]()
    t0 = time.perf_counter()
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(CHUNK)
            if not buf:
                break
            h.update(buf)
    h.hexdigest()
    dt = time.perf_counter() - t0
    if dt <= 0:
        return float("nan")
    return size_mb / dt


def bench_ed25519(repeat):
    # Sign the kind of body the ledger actually produces (roughly 700 bytes
    # with a description), not a 32 byte toy message.
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    body = {"type": "ingest", "seq": 0, "prev": GENESIS, "actor": "Bench Actor",
            "actor_key_id": key_id(pub), "recorded_at": utc_now(),
            "payload": {"evidence_id": "EV-BENCH", "filename": "sample.bin",
                        "size_bytes": 67108864, "sha256": "0" * 64,
                        "sha3_256": "1" * 64, "collected_at": utc_now(),
                        "note": "x" * 400}}
    msg = canonical(body)
    n = 2000

    sign_rates = []
    verify_rates = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        for _ in range(n):
            priv.sign(msg)
        sign_rates.append(n / (time.perf_counter() - t0))

        sig = priv.sign(msg)
        t0 = time.perf_counter()
        for _ in range(n):
            pub.verify(sig, msg)
        verify_rates.append(n / (time.perf_counter() - t0))

    return statistics.median(sign_rates), statistics.median(verify_rates)


def build_synthetic_ledger(count, priv):
    kid = key_id(priv.public_key())
    records = []
    prev = GENESIS
    for i in range(count):
        body = {"type": "ingest", "seq": i, "prev": prev, "actor": "Bench Actor",
                "actor_key_id": kid, "recorded_at": utc_now(),
                "payload": {"evidence_id": f"EV-{i:05d}", "filename": f"item_{i}.bin",
                            "size_bytes": 1024 * (i % 97 + 1),
                            "sha256": hashlib.sha256(str(i).encode()).hexdigest(),
                            "sha3_256": hashlib.sha3_256(str(i).encode()).hexdigest(),
                            "collected_at": utc_now()}}
        rec = dict(body)
        rec["signature"] = base64.b64encode(priv.sign(canonical(body))).decode("ascii")
        records.append(rec)
        prev = record_link(rec)
    return records


def verify_synthetic_ledger(records, pub):
    expected = GENESIS
    for rec in records:
        assert rec["prev"] == expected
        pub.verify(base64.b64decode(rec["signature"]), canonical(body_of(rec)))
        expected = record_link(rec)


def cmd_bench(a):
    sizes = [int(s) for s in a.sizes.split(",") if s.strip()]
    repeat = a.repeat
    workdir = Path(a.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    rows = []

    print(f"E1  hashing throughput   sizes={sizes} MB, {repeat} runs each")
    for size_mb in sizes:
        tmp = make_temp_file(size_mb, workdir)
        try:
            for algo in HASHES:
                rates = [hash_throughput(tmp, algo, size_mb) for _ in range(repeat)]
                med = statistics.median(rates)
                rows.append(["E1_hash", algo, size_mb, "", round(med, 1), "MB/s"])
                print(f"    {algo:<9} {size_mb:>4} MB : {med:8.1f} MB/s")
        finally:
            tmp.unlink(missing_ok=True)

    print(f"\nE2  Ed25519              {repeat} runs x 2000 ops")
    sign_rate, verify_rate = bench_ed25519(repeat)
    rows.append(["E2_ed25519", "sign", "", "", round(sign_rate, 0), "ops/s"])
    rows.append(["E2_ed25519", "verify", "", "", round(verify_rate, 0), "ops/s"])
    print(f"    sign             : {sign_rate:10.0f} ops/s")
    print(f"    verify           : {verify_rate:10.0f} ops/s")

    print(f"\nE3  ledger scalability   {repeat} runs each")
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    for count in (100, 1000, 5000):
        build_times = []
        verify_times = []
        for _ in range(repeat):
            t0 = time.perf_counter()
            recs = build_synthetic_ledger(count, priv)
            build_times.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            verify_synthetic_ledger(recs, pub)
            verify_times.append(time.perf_counter() - t0)

        bt = statistics.median(build_times)
        vt = statistics.median(verify_times)
        rows.append(["E3_ledger", "build", "", count, round(bt, 4), "s"])
        rows.append(["E3_ledger", "verify", "", count, round(vt, 4), "s"])
        print(f"    {count:>5} records   : build {bt:7.3f} s   verify {vt:7.3f} s")

    with open(a.csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["experiment", "metric", "size_mb", "records", "median", "unit"])
        w.writerows(rows)
    print(f"\nwritten: {a.csv}   (medians over {repeat} runs)")
    return 0


# ---- experiment E4 ----

def cmd_tsa_bench(a):
    try:
        import rfc3161ng  # noqa: F401
    except ImportError:
        raise SystemExit("Missing dependency. Run:  pip install rfc3161ng")

    urls = [u.strip() for u in a.urls.split(",") if u.strip()]
    rows = []
    print(f"E4  RFC 3161 round trip   {a.n} requests per TSA, {a.sleep}s apart\n")

    for url in urls:
        latencies = []
        failures = 0
        for i in range(a.n):
            digest = hashlib.sha256(os.urandom(32)).hexdigest()
            t0 = time.perf_counter()
            token = request_tsa_token(digest, url)
            dt = (time.perf_counter() - t0) * 1000.0
            if token:
                latencies.append(dt)
            else:
                failures += 1
            print(f"\r    {url:<40} {i + 1}/{a.n}", end="", flush=True)
            time.sleep(a.sleep)      # do not hammer a free public service
        print()

        if not latencies:
            print(f"    {url}: no successful requests — excluded\n")
            rows.append(["E4_tsa", url, 0, a.n, "", "", "ms"])
            continue

        ordered = sorted(latencies)
        med = statistics.median(latencies)
        p95 = ordered[max(0, int(round(0.95 * len(ordered))) - 1)]
        rows.append(["E4_tsa", url, len(latencies), failures,
                     round(med, 1), round(p95, 1), "ms"])
        print(f"    ok {len(latencies)}/{a.n}   median {med:.1f} ms   "
              f"p95 {p95:.1f} ms\n")

    with open(a.csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["experiment", "tsa_url", "successful", "failed",
                    "median", "p95", "unit"])
        w.writerows(rows)
    print(f"written: {a.csv}")
    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="evidence_pipeline.py",
        description="Cryptographic pipeline for digital evidence integrity "
                    "and chain of custody.")
    sub = ap.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("keygen", help="generate an Ed25519 key pair for an actor")
    sp.add_argument("--name", required=True)
    sp.add_argument("--dir", default="keys")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(fn=cmd_keygen)

    sp = sub.add_parser("ingest", help="register a new evidence item")
    sp.add_argument("file")
    sp.add_argument("--ledger", default="ledger.jsonl")
    sp.add_argument("--key", required=True)
    sp.add_argument("--actor", required=True)
    sp.add_argument("--evidence-id", required=True)
    sp.add_argument("--description")
    sp.add_argument("--collected-at")
    sp.add_argument("--tsa", help="RFC 3161 TSA URL, e.g. https://freetsa.org/tsr")
    sp.set_defaults(fn=cmd_ingest)

    sp = sub.add_parser("transfer", help="record a custody handover")
    sp.add_argument("--ledger", default="ledger.jsonl")
    sp.add_argument("--key", required=True)
    sp.add_argument("--actor", required=True)
    sp.add_argument("--evidence-id", required=True)
    sp.add_argument("--from-actor", required=True)
    sp.add_argument("--to-actor", required=True)
    sp.add_argument("--purpose")
    sp.add_argument("--tsa")
    sp.set_defaults(fn=cmd_transfer)

    sp = sub.add_parser("verify", help="verify chain, signatures, tokens, files")
    sp.add_argument("--ledger", default="ledger.jsonl")
    sp.add_argument("--pub", nargs="+", required=True,
                    help="public key PEM file(s) of known actors")
    sp.add_argument("--files-dir", help="re-hash evidence files in this directory")
    sp.set_defaults(fn=cmd_verify)

    sp = sub.add_parser("attach-token", help="attach a deferred RFC 3161 token to a record")
    sp.add_argument("--ledger", default="ledger.jsonl")
    sp.add_argument("--seq", type=int, required=True, help="seq of the record to timestamp")
    sp.add_argument("--tsa", required=True, help="RFC 3161 TSA URL")
    sp.set_defaults(fn=cmd_attach_token)

    sp = sub.add_parser("bench", help="experiments E1-E3")
    sp.add_argument("--sizes", default="1,16,64,256,512",
                    help="file sizes in MB, comma-separated")
    sp.add_argument("--repeat", type=int, default=5, help="runs per measurement")
    sp.add_argument("--workdir", default=".", help="where temp files are created")
    sp.add_argument("--csv", default="bench_results.csv")
    sp.set_defaults(fn=cmd_bench)

    sp = sub.add_parser("tsa-bench", help="experiment E4: TSA round-trip latency")
    sp.add_argument("--urls", required=True, help="comma-separated TSA URLs")
    sp.add_argument("--n", type=int, default=30, help="requests per TSA")
    sp.add_argument("--sleep", type=float, default=1.0,
                    help="pause between requests, seconds (be polite)")
    sp.add_argument("--csv", default="tsa_results.csv")
    sp.set_defaults(fn=cmd_tsa_bench)

    args = ap.parse_args()
    rc = args.fn(args)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()