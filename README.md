# Evidence Integrity Pipeline

`evidence_pipeline.py` hashes an evidence file, signs the resulting record with an
Ed25519 key, optionally timestamps it through a public RFC 3161 authority, and
appends it to a hash-chained custody ledger. Every handover afterwards is another
signed record in the same chain, so editing the file, editing a record or swapping
two records around all show up when you run `verify`.

No blockchain, no daemon, no database. One script, one JSON Lines file, and
primitives that a court expert can check with `openssl` alone.

Code and raw measurements for *A Cryptographic Pipeline for Integrity Assurance
and Chain of Custody of Digital Evidence* (UkrCrypto2026).

## Requirements

Python 3.8 or newer and `cryptography` (46.0.5 for the numbers reported here).
The floor is 3.8 because of a single `Path.unlink(missing_ok=True)`; nothing in
the file needs newer syntax. Everything below was run on CPython 3.14.3.

`rfc3161ng` is only needed for timestamps. Without it, hashing, signing and
verification all still work: `ingest --tsa` warns on stderr and stores the record
without a token, `attach-token` refuses and leaves the ledger untouched, and
`tsa-bench` stops with a message about the missing dependency.

```
pip install -r requirements.txt
```

## Commands

`keygen` (Ed25519 key pair for one actor), `ingest` (register an evidence item),
`transfer` (record a handover), `attach-token` (add a deferred RFC 3161 token to a
record that already exists), `verify` (chain links, signatures and evidence files;
tokens are checked separately with openssl, see below), `bench` (experiments
E1-E3), `tsa-bench` (experiment E4).

`python evidence_pipeline.py <command> --help` for the options.

## Walkthrough

```
> python -c "import os;open('photo_001.jpg','wb').write(os.urandom(2415000))"
> python -c "import os;open('video_002.bin','wb').write(os.urandom(50*1024*1024))"

> python evidence_pipeline.py keygen --name investigator
private key : keys\investigator_ed25519.pem
public key  : keys\investigator_ed25519.pub.pem
key id      : a277cc266b753cf7

> python evidence_pipeline.py keygen --name expert
private key : keys\expert_ed25519.pem
public key  : keys\expert_ed25519.pub.pem
key id      : 120add3e13fd3622

> python evidence_pipeline.py ingest photo_001.jpg --key keys/investigator_ed25519.pem --actor "Investigator A" --evidence-id EV-0001
ingested   : photo_001.jpg  (2,415,000 bytes in 0.03s)
evidence   : EV-0001
sha256     : 90ba0ca0d589e76ce03f86fcbae2adc50acb87d73b60cdee9d8ed7075a479bd0
sha3-256   : 20adda436a56169124565645090bad3c08b9d221cbd6fdd28fd57488d7fe70d6
seq        : 0   prev: GENESIS...
timestamp  : none (deferred)

> python evidence_pipeline.py ingest video_002.bin --key keys/investigator_ed25519.pem --actor "Investigator A" --evidence-id EV-0002
ingested   : video_002.bin  (52,428,800 bytes in 0.38s)
evidence   : EV-0002
sha256     : ccb2447767f686604d85a490e7d6a9dccd311c7924a2dbd757ed9c8b670e033e
sha3-256   : a14f43e406dddaef3f47fec0f4a6bd1af93fa97c4a7844625762de26807b0d51
seq        : 1   prev: 7ec48c411a46f411...
timestamp  : none (deferred)

> python evidence_pipeline.py transfer --key keys/investigator_ed25519.pem --actor "Investigator A" --evidence-id EV-0002 --from-actor "Investigator A" --to-actor "Expert B" --purpose "forensic examination"
transfer   : EV-0002  Investigator A -> Expert B
seq        : 2   prev: 05696c4a316e7ba3...
timestamp  : none (deferred)

> python evidence_pipeline.py verify --pub keys/investigator_ed25519.pub.pem keys/expert_ed25519.pub.pem --files-dir .
records          : 3
chain head       : 89601ba306fc5f18fdce15d22750982076325ad524acb71e6edb91101921358d
evidence files   : 2 re-hashed

LEDGER VALID
```

Both evidence files above are random bytes, so the whole session can be replayed
from an empty directory; only the key ids, the hashes and the timings will differ.

`verify` needs the public key of every actor that signed something, so pass all of
them at once. It exits 0 on a valid ledger and 1 on anything it cannot confirm,
which is what you want in a script.

## Reproducing the functional evaluation (paper, Section 7.2)

Two evidence items, one handover, one deferred token.

```
python evidence_pipeline.py keygen --name investigator
python evidence_pipeline.py keygen --name expert

# the paper used a real JPEG of 261,839 bytes; a file of the same size does
# just as well, since nothing here depends on the contents
python -c "import os;open('photo_001.jpg','wb').write(os.urandom(261839))"
python -c "import os;open('video_002.bin','wb').write(os.urandom(50*1024*1024))"

python evidence_pipeline.py ingest photo_001.jpg --key keys/investigator_ed25519.pem \
    --actor "Investigator A" --evidence-id EV-0001 --tsa https://freetsa.org/tsr
python evidence_pipeline.py ingest video_002.bin --key keys/investigator_ed25519.pem \
    --actor "Investigator A" --evidence-id EV-0002 --tsa https://freetsa.org/tsr

# handover recorded without a token, on purpose
python evidence_pipeline.py transfer --key keys/investigator_ed25519.pem \
    --actor "Investigator A" --evidence-id EV-0002 \
    --from-actor "Investigator A" --to-actor "Expert B" --purpose "forensic examination"

# the token arrives later; the chain link must not move
python evidence_pipeline.py attach-token --seq 2 --tsa https://freetsa.org/tsr

python evidence_pipeline.py verify \
    --pub keys/investigator_ed25519.pub.pem keys/expert_ed25519.pub.pem --files-dir .
```

The commands above are wrapped with a trailing `\`, which is a shell convention;
in cmd or PowerShell put each one on a single line instead.

`attach-token` prints the chain link of record 2 before and after the token is
written, followed by `chain link unchanged`. That line is the whole point of keeping
`tsa_token` outside the hashed unit: if it appeared instead, every later record
would have to be re-chained and re-signed.

## Tamper detection

Actual output. Each case was run against its own copy of a clean three-record
ledger, so the chain values below are from that run, not from the walkthrough.

Evidence file modified after ingest:

```
LEDGER INVALID
  - record 0: file content mismatch: photo_001.jpg
```

One field edited inside record 1 (`--files-dir` omitted, so only the ledger is
checked). The signature fails, and because the record is interior, the next link
fails too:

```
LEDGER INVALID
  - record 1: invalid signature (actor 'Investigator A')
  - record 2: broken chain link (prev=f521fcc33b4d7c82..., expected=56cc9ec7bcca801c...)
```

Records 1 and 2 swapped. Both signatures are still valid, since neither record was
touched, but the chain no longer lines up:

```
LEDGER INVALID
  - record 2: broken chain link (prev=f521fcc33b4d7c82..., expected=0310fa721af86992...)
  - record 1: broken chain link (prev=0310fa721af86992..., expected=84f95b9886291a21...)
```

Record 1 deleted outright: one broken link, at record 2.

Trailing records deleted: **still `LEDGER VALID`**. A prefix of a hash chain is a
valid hash chain, and nothing inside the ledger records how long it was supposed
to be. See Section 8, Remark 1; the fix is external (publish the chain head, or
timestamp it) and is out of scope here.

## Performance measurements

```
python evidence_pipeline.py bench --sizes 1,16,64,256,512 --repeat 5 --csv bench_results.csv
python evidence_pipeline.py tsa-bench \
    --urls "https://freetsa.org/tsr,http://timestamp.digicert.com,http://timestamp.sectigo.com" \
    --n 30 --sleep 1 --csv tsa_results.csv
```

`bench_results.csv` and `tsa_results.csv` in this repository are the raw numbers
reported in the paper, measured on an Intel Xeon E-2276M with 16 GB of RAM and a
Samsung PM961 NVMe SSD, under Windows 10 Pro 22H2 and CPython 3.14.3.

Two things to keep in mind before comparing your numbers with ours. `bench` writes
a temp file of each requested size into `--workdir` and `fsync`s it, so the 512 MB
run needs the space and the throughput depends on the filesystem and on what the
page cache happens to hold; and `tsa-bench` measures somebody else's servers over
your network, so E4 is a property of the route, not of the code. `--sleep 1` is
there to stay welcome at the free services.

## Checking a token with openssl

Records store the RFC 3161 token as base64 of its DER encoding. Decode it, then
verify against the digest of the record body -- the same digest the token was
requested over, i.e. SHA-256 of the canonical JSON of the body without the
`signature` and `tsa_token` fields:

```python
import base64, json
rec = json.loads(open("ledger.jsonl").readlines()[2])   # the record you want
open("token.der", "wb").write(base64.b64decode(rec["tsa_token"]))
```

```
openssl ts -verify -digest <sha256-hex-of-record-body> \
    -token_in -in token.der -CAfile cacert.pem -untrusted tsa.crt
```

`-token_in` matters. What is stored is the bare `TimeStampToken`, not the
`TimeStampResp` that a `.tsr` file holds, and without the flag openssl tries to
parse the token as a response and fails with a confusing ASN.1 error about
`status_info`. FreeTSA publishes `cacert.pem` and `tsa.crt` at
https://freetsa.org/.

This is the authoritative check. `verify` also looks at tokens in process, but
only to confirm that they parse and to read the time out of them: current
`rfc3161ng` releases expose no accessor for the imprint, so the comparison against
the record digest is skipped and nothing about tokens appears in the output.

## Ledger format

JSON Lines, one canonical record per line, appended and never rewritten (the sole
exception is `attach-token`, which rewrites the file to add one field). Canonical
means UTF-8, keys sorted and no whitespace, so that signer and verifier hash
identical bytes. Lines are terminated with LF on every platform, which keeps the
file itself byte-identical across machines; the line ending is not part of what
gets signed.

```json
{
  "actor": "Investigator A",
  "actor_key_id": "a277cc266b753cf7",
  "payload": {
    "evidence_id": "EV-0002",
    "from_actor": "Investigator A",
    "purpose": "forensic examination",
    "to_actor": "Expert B"
  },
  "prev": "05696c4a316e7ba3e69f0d9c07d7f3d8760e0f310e644668ca96fbd32cb56efc",
  "recorded_at": "2026-07-31T08:18:10Z",
  "seq": 2,
  "signature": "6+iMBv3MBxX3B6J8EOV9Anb7Cd4NGn3DfVD/Q3HQchvVA2V7utx5RIePTDavqSGVr0Q4rrCWFZh1O/1bqclUBA==",
  "type": "transfer"
}
```

`signature` is Ed25519 over the canonical body, that is over everything above
except `signature` and `tsa_token`. `prev` is SHA-256 of the canonical body of the
previous record together with its signature, and `GENESIS` in record 0.
`actor_key_id` is the first 16 hex characters of SHA-256 of the raw public key, so
`verify` can pick the right key out of the ones given to `--pub`.

An `ingest` payload carries `evidence_id`, `filename`, `size_bytes`, `sha256`,
`sha3_256`, `collected_at` and an optional `description`; a `transfer` payload
carries `evidence_id`, `from_actor`, `to_actor` and `purpose`.

## Limitations worth stating out loud

- Private keys are written as unencrypted PKCS#8. On POSIX `keygen` follows up with
  `chmod 0600`; on Windows that call does nothing useful and the file inherits the
  permissions of `keys/`. Either way it is fine for reproducing the experiments and
  wrong for real casework, where the signing key belongs on a smart card or an HSM.
- `ingest` and `transfer` read the whole ledger to compute `prev` and then append,
  with no locking. Two processes writing the same ledger at the same time will
  produce two records claiming the same `seq`. One writer at a time.
- Truncation of trailing records is not detectable from the ledger alone, as above.
- `verify` reports every problem it finds and does not stop at the first one,
  except when a record is missing structural fields; there it stops, because
  nothing after that point can be interpreted.

## License

Public domain, see `LICENSE` (the Unlicense). Use it for anything, no attribution
required. A citation of the paper is welcome but not owed.
