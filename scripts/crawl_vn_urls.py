import csv
import gzip
import io
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests
from tqdm import tqdm

LOC_REGEX = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

SITES: dict[str, list[str]] = {
    "vnexpress.net": [
        "https://vnexpress.net/google-news-sitemap.xml",
        "https://vnexpress.net/sitemap.xml",
    ],
    "tuoitre.vn": [
        "https://tuoitre.vn/sitemaps/index.rss",
        "https://tuoitre.vn/sitemaps/latest-news.rss",
        "https://tuoitre.vn/sitemap.xml",
    ],
    "thanhnien.vn": [
        "https://thanhnien.vn/sitemap.xml",
    ],
    "cafef.vn": [
        "https://cafef.vn/sitemap.xml",
    ],
    "dantri.com.vn": [
        "https://dantri.com.vn/sitemaps/articles.xml",
        "https://dantri.com.vn/sitemaps/category-sitemap.xml",
        "https://dantri.com.vn/sitemap.xml",
    ],
    "vietnamnet.vn": [
        "https://vietnamnet.vn/sitemap.xml",
    ],
    "kenh14.vn": [
        "https://kenh14.vn/sitemap.xml",
    ],
    "znews.vn": [
        "https://znews.vn/sitemap/sitemap.xml",
    ],
    "baomoi.com": [
        "https://baomoi.com/sitemaps/sitemap.xml",
    ],
    "laodong.vn": [
        "https://laodong.vn/sitemap.xml",
    ],
}

MAX_URLS_PER_SITE = 3000
REQUEST_TIMEOUT = 10
SLEEP_BETWEEN_REQUESTS = 0.5
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

OUTPUT_PATH = os.path.join("data", "vn_benign_crawled.csv")


def fetch_xml(url: str) -> bytes | None:
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "application/xml, text/xml, */*"},
        )
        resp.raise_for_status()
        content = resp.content
        if url.endswith(".gz") or content[:2] == b"\x1f\x8b":
            try:
                content = gzip.decompress(content)
            except OSError:
                pass
        ctype = (resp.headers.get("content-type") or "").lower()
        stripped = content.lstrip()[:200].lower()
        if (b"<html" in stripped or b"<!doctype html" in stripped) and "xml" not in ctype:
            print(f"  [WARN] Non-XML (HTML) response for {url}; skipping", flush=True)
            return None
        return content
    except requests.RequestException as e:
        print(f"  [WARN] Fetch failed for {url}: {e}", flush=True)
        return None


def regex_extract_locs(xml_bytes: bytes) -> list[str]:
    try:
        text = xml_bytes.decode("utf-8", errors="replace")
    except Exception:
        return []
    return [m.strip() for m in LOC_REGEX.findall(text)]


def parse_sitemap(xml_bytes: bytes) -> tuple[list[str], list[str]]:
    sitemap_urls: list[str] = []
    page_urls: list[str] = []

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        print(f"  [WARN] XML parse error: {e}; falling back to regex", flush=True)
        for txt in regex_extract_locs(xml_bytes):
            if txt.endswith(".xml") or txt.endswith(".xml.gz") or txt.endswith(".rss"):
                sitemap_urls.append(txt)
            elif txt.startswith("http"):
                page_urls.append(txt)
        return sitemap_urls, page_urls

    tag = root.tag.lower()

    if tag.endswith("sitemapindex"):
        for sm in root.findall("sm:sitemap", NS):
            loc = sm.find("sm:loc", NS)
            if loc is not None and loc.text:
                sitemap_urls.append(loc.text.strip())
    elif tag.endswith("urlset"):
        for u in root.findall("sm:url", NS):
            loc = u.find("sm:loc", NS)
            if loc is not None and loc.text:
                page_urls.append(loc.text.strip())
    else:
        for elem in root.iter():
            local_tag = elem.tag.split("}")[-1].lower()
            if local_tag in ("loc", "link") and elem.text:
                txt = elem.text.strip()
                if txt.endswith(".xml") or txt.endswith(".xml.gz") or txt.endswith(".rss"):
                    sitemap_urls.append(txt)
                elif txt.startswith("http"):
                    page_urls.append(txt)

    return sitemap_urls, page_urls


def crawl_site(site_name: str, candidates: list[str], max_urls: int) -> list[str]:
    print(f"\n[CRAWL] {site_name}", flush=True)

    for sitemap_url in candidates:
        print(f"  Trying: {sitemap_url}", flush=True)
        xml_bytes = fetch_xml(sitemap_url)
        time.sleep(SLEEP_BETWEEN_REQUESTS)
        if xml_bytes is None:
            continue

        child_sitemaps, urls = parse_sitemap(xml_bytes)
        collected: list[str] = list(urls)

        if child_sitemaps and len(collected) < max_urls:
            print(f"  Sitemap-index: {len(child_sitemaps)} child(ren)", flush=True)
            for child in child_sitemaps:
                if len(collected) >= max_urls:
                    break
                child_bytes = fetch_xml(child)
                time.sleep(SLEEP_BETWEEN_REQUESTS)
                if child_bytes is None:
                    continue
                _, child_urls = parse_sitemap(child_bytes)
                if child_urls:
                    collected.extend(child_urls)
                    print(f"    + {len(child_urls):>5} from {child[:80]}", flush=True)

        if collected:
            collected = collected[:max_urls]
            print(f"  -> {len(collected)} URL(s) collected from {site_name}", flush=True)
            return collected

    print(f"  -> 0 URL(s) collected from {site_name} (all candidates failed)", flush=True)
    return []


def main() -> int:
    print("=" * 70)
    print("  VN BENIGN URL CRAWLER")
    print("=" * 70)

    all_urls: list[str] = []
    site_stats: list[tuple[str, int]] = []

    for site_name, candidates in tqdm(list(SITES.items()), desc="Sites", unit="site"):
        try:
            urls = crawl_site(site_name, candidates, MAX_URLS_PER_SITE)
            site_stats.append((site_name, len(urls)))
            all_urls.extend(urls)
        except Exception as e:
            print(f"  [ERROR] Unexpected failure on {site_name}: {e}", flush=True)
            site_stats.append((site_name, 0))

    print("\n" + "=" * 70)
    print("  PER-SITE TOTALS")
    print("=" * 70)
    for domain, count in site_stats:
        print(f"  {domain:<25} {count:>6} URL(s)")

    seen: set[str] = set()
    deduped: list[str] = []
    for u in all_urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    print(f"\n  Total before dedup: {len(all_urls)}")
    print(f"  Total after  dedup: {len(deduped)}")

    successful_sites = sum(1 for _, c in site_stats if c > 0)
    if successful_sites < 5:
        print(
            f"\n[ERROR] Only {successful_sites} site(s) succeeded; minimum is 5. "
            "Check network or User-Agent.",
            flush=True,
        )
        return 1

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for u in deduped:
            writer.writerow([u, 0])

    print(f"\n[OK] Saved {len(deduped)} URL(s) to '{OUTPUT_PATH}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
