import csv
import io
import os
import sys
import zipfile

import requests

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
DATA_DIR = "data"
RAW_PATH = os.path.join(DATA_DIR, "tranco_full.csv")
VN_OUT = os.path.join(DATA_DIR, "tranco_vn.csv")
GLOBAL_OUT = os.path.join(DATA_DIR, "tranco_global_top10k.csv")

GLOBAL_TOP_N = 10_000
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def download_tranco() -> str:
    if os.path.isfile(RAW_PATH):
        print(f"  Using cached Tranco list: {RAW_PATH}")
        return RAW_PATH

    print(f"  Downloading {TRANCO_URL} ...")
    r = requests.get(TRANCO_URL, headers={"User-Agent": USER_AGENT}, timeout=60)
    r.raise_for_status()
    print(f"  Downloaded {len(r.content):,} bytes")

    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        names = z.namelist()
        if not names:
            raise RuntimeError("Empty Tranco zip")
        with z.open(names[0]) as src, open(RAW_PATH, "wb") as dst:
            dst.write(src.read())
    print(f"  Extracted -> {RAW_PATH}")
    return RAW_PATH


def variants(domain: str) -> list[str]:
    return [f"https://{domain}", f"https://{domain}/", f"https://www.{domain}"]


def main() -> int:
    print("=" * 70)
    print("  TRANCO TIERED EXTRACTOR")
    print("=" * 70)

    os.makedirs(DATA_DIR, exist_ok=True)
    raw_path = download_tranco()

    print("\n  Reading Tranco list (rank,domain) ...")
    tranco: list[tuple[int, str]] = []
    with open(raw_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            try:
                rank = int(row[0])
            except ValueError:
                continue
            domain = row[1].strip().lower()
            if not domain:
                continue
            tranco.append((rank, domain))
    print(f"  Loaded {len(tranco):,} (rank, domain) pairs")

    vn_entries: list[tuple[int, str]] = []
    vn_domains_set: set[str] = set()
    for rank, dom in tranco:
        if dom.endswith(".vn"):
            vn_entries.append((rank, dom))
            vn_domains_set.add(dom)
    print(f"\n  Tier 1 (.vn TLD): {len(vn_entries):,} domains")

    global_entries: list[tuple[int, str]] = []
    for rank, dom in tranco:
        if rank > GLOBAL_TOP_N:
            break
        if dom in vn_domains_set:
            continue
        global_entries.append((rank, dom))
    print(f"  Tier 2 (rank <= {GLOBAL_TOP_N:,}, non-.vn): {len(global_entries):,} domains")

    with open(VN_OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        for _, dom in vn_entries:
            for u in variants(dom):
                w.writerow([u, 0])
    vn_url_count = len(vn_entries) * 3
    print(f"\n  Saved Tier 1: {vn_url_count:,} URL variants -> '{VN_OUT}'")

    with open(GLOBAL_OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        for _, dom in global_entries:
            for u in variants(dom):
                w.writerow([u, 0])
    global_url_count = len(global_entries) * 3
    print(f"  Saved Tier 2: {global_url_count:,} URL variants -> '{GLOBAL_OUT}'")

    print("\n" + "-" * 70)
    print(f"  {'Tier':<14} {'Filter':<28} {'Domains':>10} {'URLs':>10}")
    print(f"  {'-'*14} {'-'*28} {'-'*10} {'-'*10}")
    print(f"  {'1 (.vn)':<14} {'TLD ends with .vn':<28} {len(vn_entries):>10,} {vn_url_count:>10,}")
    print(f"  {'2 (global)':<14} {f'rank<={GLOBAL_TOP_N:,}, non-.vn':<28} "
          f"{len(global_entries):>10,} {global_url_count:>10,}")
    total_domains = len(vn_entries) + len(global_entries)
    total_urls = vn_url_count + global_url_count
    print(f"  {'TOTAL':<14} {'':<28} {total_domains:>10,} {total_urls:>10,}")

    print("\n  Top 20 .vn domains by Tranco rank:")
    print(f"  {'Rank':>7}  Domain")
    print(f"  {'-'*7}  {'-'*40}")
    for rank, dom in vn_entries[:20]:
        print(f"  {rank:>7}  {dom}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
