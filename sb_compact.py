#!/usr/bin/env python3
"""
sb_compact.py — Chromium SafeBrowsing V4 database compactor.

Converts a standard UrlSoceng.store.4_XXX database to a compact format:
  Step 1 — Truncate 4-byte hash prefixes to 3 bytes and deduplicate.
            This yields ~12% fewer entries (collisions), raw size drops ~30%.
  Step 2 — Compress the resulting protobuf with zstd level 3.
            Combined result: ~56% of original size, 100% threat coverage.

Trade-off warning
-----------------
  False-positive rate rises from ~0.10% to ~24% per URL lookup.
  Roughly 1 in 4 safe URL lookups will trigger a server-side full-hash
  confirmation request to Google's Safe Browsing API.

  The Google Safe Browsing API MUST be reachable at runtime.
  Do NOT use this for fully offline / no-network deployments.

Output files (placed in --output dir)
--------------------------------------
  UrlSoceng.store.compact      — companion metadata (.store replacement)
  UrlSoceng.store.compact.zst  — compressed 3-byte hash database

Usage
-----
  python sb_compact.py \\
      --input  UrlSoceng.store.4_13409054587077876 \\
      --store  UrlSoceng.store \\
      --output ./compact/

  Optional flags:
    --level  1-19    zstd compression level (default 3 — fast, near-optimal)
    --dry-run        print stats only, do not write files
    --verify         after writing, decompress and check SHA-256 + sort order

Requirements
------------
  libzstd.so.1 must be installed (standard on Ubuntu/Debian/Fedora).
  No Python packages needed — uses only stdlib + system libzstd via ctypes.

  Install if missing:
    apt install libzstd1        (Debian/Ubuntu)
    yum install libzstd         (RHEL/Fedora)
"""

import argparse
import ctypes
import hashlib
import struct
import sys
import time
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# zstd  (system libzstd via ctypes — no pip dependency)
# ─────────────────────────────────────────────────────────────────────────────

_ZSTD_CANDIDATES = [
    "/lib/x86_64-linux-gnu/libzstd.so.1",
    "/usr/lib/x86_64-linux-gnu/libzstd.so.1",
    "/usr/lib/libzstd.so.1",
    "/usr/lib64/libzstd.so.1",
    "libzstd.so.1",
    "libzstd.so",
]


def _load_zstd():
    for path in _ZSTD_CANDIDATES:
        try:
            lib = ctypes.CDLL(path)
            lib.ZSTD_versionString.restype       = ctypes.c_char_p
            lib.ZSTD_compressBound.restype       = ctypes.c_size_t
            lib.ZSTD_compress.restype            = ctypes.c_size_t
            lib.ZSTD_decompress.restype          = ctypes.c_size_t
            lib.ZSTD_isError.restype             = ctypes.c_uint
            lib.ZSTD_getErrorName.restype        = ctypes.c_char_p
            lib.ZSTD_getFrameContentSize.restype = ctypes.c_uint64
            return lib
        except OSError:
            continue
    return None


_ZSTD       = _load_zstd()
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"   # standard zstd frame magic


def zstd_available() -> bool:
    return _ZSTD is not None


def zstd_compress(data: bytes, level: int = 3) -> bytes:
    if _ZSTD is None:
        raise RuntimeError("libzstd not found")
    bound = _ZSTD.ZSTD_compressBound(len(data))
    out   = (ctypes.c_char * bound)()
    n     = _ZSTD.ZSTD_compress(out, bound, data, len(data), level)
    if _ZSTD.ZSTD_isError(n):
        raise RuntimeError(_ZSTD.ZSTD_getErrorName(n).decode())
    return bytes(out[:n])


def zstd_decompress(data: bytes) -> bytes:
    if _ZSTD is None:
        raise RuntimeError("libzstd not found")
    size = _ZSTD.ZSTD_getFrameContentSize(data, len(data))
    if size in ((1 << 64) - 1, (1 << 64) - 2):
        raise RuntimeError("Cannot determine decompressed size from zstd frame")
    out = (ctypes.c_char * size)()
    n   = _ZSTD.ZSTD_decompress(out, size, data, len(data))
    if _ZSTD.ZSTD_isError(n):
        raise RuntimeError(_ZSTD.ZSTD_getErrorName(n).decode())
    return bytes(out[:n])


# ─────────────────────────────────────────────────────────────────────────────
# Minimal protobuf encoder/decoder  (stdlib only)
# ─────────────────────────────────────────────────────────────────────────────

def _rv(data: bytes, pos: int):
    """Read a varint. Returns (value, new_pos)."""
    result = shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _wv(v: int) -> bytes:
    """Write a varint."""
    out = []
    while v > 0x7F:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _fb(field: int, data: bytes) -> bytes:
    return _wv((field << 3) | 2) + _wv(len(data)) + data

def _fv(field: int, value: int) -> bytes:
    return _wv((field << 3) | 0) + _wv(value)

def _f32(field: int, value: int) -> bytes:
    return _wv((field << 3) | 5) + struct.pack("<I", value)


# ─────────────────────────────────────────────────────────────────────────────
# V4 SafeBrowsing constants
# ─────────────────────────────────────────────────────────────────────────────

_MAGIC   = 0x600DF00D   # V4StoreFileFormat magic
_VERSION = 9            # format version (Chromium M120+)


# ─────────────────────────────────────────────────────────────────────────────
# Parser: find sorted hash prefix bytes anywhere in a V4 store file
# ─────────────────────────────────────────────────────────────────────────────

def _is_hash_blob(payload: bytes, ps: int) -> bool:
    """
    Return True if payload looks like a flat list of sorted hash prefixes.

    Samples from start, middle, and END of the blob so that databases
    whose first entries happen to be near 0x00000000 are not rejected.
    The 'spans_range' check uses the last sampled value (not the first 5),
    which ensures values actually spread across the full address space.
    """
    n = len(payload) // ps
    if n < 100 or len(payload) % ps != 0:
        return False
    idx = (
        list(range(min(30, n))) +
        [n // 2 + i for i in range(min(10, n // 2))] +
        [n - 1 - i  for i in range(min(15, n))]
    )
    idx  = sorted(set(i for i in idx if 0 <= i < n))
    vals = [int.from_bytes(payload[i * ps:(i + 1) * ps], "big") for i in idx]
    sorted_ok   = all(vals[i] <= vals[i + 1] for i in range(len(vals) - 1))
    spans_range = vals[-1] > (1 << (ps * 8 - 1))   # last value in upper half
    return sorted_ok and spans_range


def _find_hash_blob(data: bytes, depth: int = 0) -> tuple[int, bytes]:
    """
    Recursively walk protobuf fields and return (prefix_size, raw_bytes)
    for the largest blob that passes the sorted-hash check.

    The nesting path in a Chromium-written file is:
      V4StoreFileFormat (F4=LUR) → ListUpdateResponse (F8=TES)
      → ThreatEntrySet (F1=RH) → RawHashes (F2=raw data)
    """
    best_ps, best_bytes = 4, b""
    pos = 0

    while pos < len(data):
        try:
            tag_pos = pos
            tag, pos = _rv(data, pos)
            wt = tag & 7

            if wt == 0:
                _, pos = _rv(data, pos)

            elif wt == 2:
                l, dstart = _rv(data, pos)
                pos = dstart + l
                if pos > len(data):
                    break
                payload = data[dstart:dstart + l]

                # Direct check: is this field the hash blob?
                for ps in (4, 3, 5):
                    if l > len(best_bytes) and _is_hash_blob(payload, ps):
                        best_bytes = payload
                        best_ps    = ps

                # Recurse into nested fields that aren't already the hash blob
                if depth < 8 and 4 < l < 60_000_000 and l != len(best_bytes):
                    sub_ps, sub_bytes = _find_hash_blob(payload, depth + 1)
                    if len(sub_bytes) > len(best_bytes):
                        best_bytes = sub_bytes
                        best_ps    = sub_ps

            elif wt == 5:
                pos = tag_pos + 5
            elif wt == 1:
                pos = tag_pos + 9
            else:
                pos = tag_pos + 1   # skip unknown wire type

        except Exception:
            break

    return best_ps, best_bytes


def extract_hashes(filepath: str) -> tuple[int, bytes]:
    """
    Read a V4StoreFileFormat file (plain or zstd-compressed) and return
    (prefix_size, raw_bytes).  raw_bytes is the flat sorted hash prefix data.
    """
    data = Path(filepath).read_bytes()

    if data[:4] == _ZSTD_MAGIC:
        print("[parse] zstd-compressed input, decompressing...")
        data = zstd_decompress(data)

    mb = len(data) / 1024 / 1024
    prefix_size, raw_bytes = _find_hash_blob(data)

    if len(raw_bytes) < prefix_size * 100:
        raise ValueError(
            "Could not locate hash prefix data.\n"
            "The file may use Rice-Golomb encoding (served directly from the\n"
            "Safe Browsing API, not yet decoded by Chromium). Start Chromium\n"
            "once so it decodes and caches the DB, then use those files."
        )

    n = len(raw_bytes) // prefix_size
    print(f"[parse] {mb:.2f} MB  →  {n:,} {prefix_size}-byte prefixes")
    return prefix_size, raw_bytes


# ─────────────────────────────────────────────────────────────────────────────
# Transform: 4-byte → 3-byte with deduplication
# ─────────────────────────────────────────────────────────────────────────────

def truncate_to_3bytes(raw4: bytes) -> bytes:
    """
    Keep only the high 3 bytes of each 4-byte prefix, deduplicate, and
    return the result as a flat sorted byte string.

    Why no re-sort is needed
    ────────────────────────
    Input is sorted big-endian 4-byte integers.  Two entries that share
    the same top 3 bytes are adjacent in the sorted input; the first one
    is already the smallest representative.  Dropping the last byte
    therefore preserves lexicographic order.

    False-positive impact
    ─────────────────────
    Any URL whose SHA-256 starts with the same 3 bytes will now match
    this entry, raising the per-lookup false-positive rate from ~0.10%
    (4-byte) to ~24% (3-byte).  Chromium resolves false positives via a
    server full-hash check, so the Google API must remain reachable.
    """
    assert len(raw4) % 4 == 0
    seen   = set()
    result = []
    for i in range(0, len(raw4), 4):
        p = raw4[i : i + 3]
        if p not in seen:
            seen.add(p)
            result.append(p)
    return b"".join(result)


# ─────────────────────────────────────────────────────────────────────────────
# Writer: build valid V4StoreFileFormat protobuf from 3-byte prefixes
# ─────────────────────────────────────────────────────────────────────────────

def _build_data_proto(raw3: bytes) -> bytes:
    """
    Pack raw3 into the V4StoreFileFormat protobuf that Chromium expects.

    Nesting:
      V4StoreFileFormat {
        magic (F1/fixed32), version (F2/fixed32),
        list_update_response (F4) {
          threat_type=5, entry_type=1, platform_type=6, response_type=2,
          additions (F8) { raw_hashes (F1) { prefix_size=3, raw_hashes=<raw3> } }
          new_client_state=b'001'
        }
        checksum (F5) { sha256=SHA256(raw3) }
      }
    """
    rh_msg  = _fv(1, 3)  + _fb(2, raw3)
    tes_msg = _fb(1, rh_msg)
    lur_msg = (
        _fv(1, 5) + _fv(2, 1) + _fv(3, 6) + _fv(7, 2) +
        _fb(8, tes_msg) + _fb(10, b"001")
    )
    chk_msg = _fb(1, hashlib.sha256(raw3).digest())
    return _f32(1, _MAGIC) + _f32(2, _VERSION) + _fb(4, lur_msg) + _fb(5, chk_msg)


def _build_store_meta(data_filename: str, sha256_of_raw3: bytes) -> bytes:
    """Build the small companion .store metadata file."""
    list_id  = _fv(1, 5) + _fv(2, 6) + _fv(3, 1) + _fb(4, b"001")
    chk_msg  = _fb(1, sha256_of_raw3)
    lur_inner = _fb(1, list_id) + _fv(4, 2) + _fb(8, chk_msg)
    file_ref  = _fv(1, 4) + _fb(2, data_filename.encode("ascii"))
    return (_f32(1, _MAGIC) + _f32(2, _VERSION) +
            _fb(3, lur_inner) + _fb(4, file_ref))


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _mb(n: int) -> str:
    return f"{n / 1024 / 1024:.3f} MB"


def parse_args():
    p = argparse.ArgumentParser(
        description="Compact a Chromium SafeBrowsing V4 database (3-byte + zstd).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--input",   required=True, help="Path to .store.4_XXXX data file")
    p.add_argument("--store",   required=True, help="Path to companion .store file")
    p.add_argument("--output",  default=".",   help="Output directory (default: .)")
    p.add_argument("--level",   type=int, default=3,
                   help="zstd level 1–19  (default 3)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print stats only, write nothing")
    p.add_argument("--verify",  action="store_true",
                   help="After writing, decompress and verify integrity")
    return p.parse_args()


def main():
    args = parse_args()

    if not zstd_available():
        sys.exit(
            "ERROR: libzstd not found.\n"
            "  apt install libzstd1    (Debian/Ubuntu)\n"
            "  yum install libzstd     (RHEL/Fedora)"
        )

    input_path = Path(args.input)
    output_dir = Path(args.output)

    for p in (input_path, Path(args.store)):
        if not p.exists():
            sys.exit(f"ERROR: {p} not found")

    # 1 ── Parse
    t0 = time.time()
    prefix_size, raw_bytes = extract_hashes(str(input_path))
    n_orig = len(raw_bytes) // prefix_size
    print(f"[parse]    {n_orig:>10,} entries  ({_mb(len(raw_bytes))})  "
          f"in {time.time()-t0:.2f}s")

    # 2 ── Truncate 4→3 bytes
    if prefix_size == 3:
        print("[truncate] Input already 3-byte, skipping.")
        raw3 = raw_bytes
    elif prefix_size == 4:
        t0 = time.time()
        raw3  = truncate_to_3bytes(raw_bytes)
        n3    = len(raw3) // 3
        dupes = n_orig - n3
        print(f"[truncate] {n_orig:>10,} → {n3:>10,} entries  "
              f"({dupes:,} collisions removed, {dupes/n_orig*100:.2f}%)  "
              f"in {time.time()-t0:.2f}s")
    else:
        sys.exit(f"ERROR: prefix_size={prefix_size} not supported (expected 3 or 4)")

    # 3 ── Build protobuf
    t0 = time.time()
    proto = _build_data_proto(raw3)
    print(f"[proto]    {_mb(len(proto))}  in {time.time()-t0:.2f}s")

    # 4 ── Compress
    t0 = time.time()
    compressed = zstd_compress(proto, level=args.level)
    print(f"[zstd-{args.level}]   {_mb(len(proto))} → {_mb(len(compressed))}  "
          f"({len(compressed)/len(proto)*100:.1f}%)  "
          f"in {time.time()-t0:.2f}s")

    # ── Summary
    orig_size  = input_path.stat().st_size
    n3_entries = len(raw3) // 3
    fp4 = n_orig      / (2 ** 32) * 100
    fp3 = n3_entries  / (2 ** 24) * 100

    print(f"\n{'─'*58}")
    print(f"  Original            : {_mb(orig_size):>12}  ({orig_size:,} bytes)")
    print(f"  3-byte proto        : {_mb(len(proto)):>12}  "
          f"({len(proto)/orig_size*100:.1f}% of original)")
    print(f"  3-byte + zstd-{args.level}    : {_mb(len(compressed)):>12}  "
          f"({len(compressed)/orig_size*100:.1f}% of original)")
    print(f"  Saved               : {_mb(orig_size-len(compressed)):>12}  "
          f"({(1-len(compressed)/orig_size)*100:.1f}% reduction)")
    print(f"\n  False-positive rate : {fp4:.3f}%  →  {fp3:.1f}%  "
          f"(~{fp3/fp4:.0f}× more API calls)")
    print(f"  ⚠  Google Safe Browsing API must remain reachable")
    print(f"{'─'*58}")

    if args.dry_run:
        print("\n[dry-run] No files written.")
        return

    # 5 ── Write
    output_dir.mkdir(parents=True, exist_ok=True)
    sha256_raw3 = hashlib.sha256(raw3).digest()
    data_fname  = "UrlSoceng.store.compact"
    data_out    = output_dir / f"{data_fname}.zst"
    store_out   = output_dir / "UrlSoceng.store.compact"

    data_out.write_bytes(compressed)
    store_out.write_bytes(_build_store_meta(data_fname, sha256_raw3))

    print(f"\n[write] {data_out}  ({len(compressed):,} bytes)")
    print(f"[write] {store_out}  ({store_out.stat().st_size} bytes)")

    # 6 ── Verify
    if args.verify:
        print("\n[verify] Checking round-trip integrity...")
        ps_rt, rb_rt = _find_hash_blob(zstd_decompress(data_out.read_bytes()))
        sha_ok     = hashlib.sha256(rb_rt).digest() == sha256_raw3
        sorted_ok  = all(rb_rt[i:i+3] <= rb_rt[i+3:i+6]
                         for i in range(0, len(rb_rt)-3, 3))
        print(f"[verify] SHA-256 : {'✓ PASS' if sha_ok    else '✗ FAIL'}")
        print(f"[verify] Sorted  : {'✓ PASS' if sorted_ok else '✗ FAIL'}")
        if not (sha_ok and sorted_ok):
            sys.exit(1)

    print(f"\nNext steps:")
    print(f"  1. Copy {data_out.name} and {store_out.name}")
    print(f"     to Chromium's Safe Browsing DB directory.")
    print(f"  2. Apply v4_store_compact.patch to Chromium source.")
    print(f"  3. Rebuild Chromium.")


if __name__ == "__main__":
    main()
