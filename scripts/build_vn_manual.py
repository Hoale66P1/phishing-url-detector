import csv
import gzip
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests

OUTPUT_PATH = os.path.join("data", "vn_benign_manual.csv")
REQUEST_TIMEOUT = 10
SLEEP_BETWEEN_REQUESTS = 0.5
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

UNIVERSITIES = [
    "uit.edu.vn", "hcmut.edu.vn", "hcmus.edu.vn", "vnu.edu.vn", "hust.edu.vn",
    "neu.edu.vn", "ftu.edu.vn", "ueh.edu.vn", "hcmute.edu.vn", "ou.edu.vn",
    "tdtu.edu.vn", "hcmuaf.edu.vn", "vinhuni.edu.vn", "dlu.edu.vn", "tlu.edu.vn",
    "iuh.edu.vn", "hub.edu.vn", "duytan.edu.vn", "hou.edu.vn", "agu.edu.vn",
    "tnu.edu.vn", "vlu.edu.vn", "hueuni.edu.vn", "udn.vn", "ctu.edu.vn",
    "hnue.edu.vn", "uth.edu.vn", "utc.edu.vn", "vku.udn.vn", "ptit.edu.vn",
]

EDU_PATHS = [
    "/", "/tuyen-sinh", "/tuyen-sinh-dai-hoc", "/tuyen-sinh-sau-dai-hoc",
    "/dao-tao", "/chuong-trinh-dao-tao", "/sinh-vien", "/can-bo-giang-vien",
    "/nghien-cuu-khoa-hoc", "/hop-tac-quoc-te", "/tin-tuc", "/thong-bao",
    "/lich-cong-tac", "/co-cau-to-chuc", "/khoa-cong-nghe-thong-tin",
    "/khoa-dien-tu-vien-thong", "/khoa-co-khi", "/khoa-kinh-te",
    "/khoa-quan-tri-kinh-doanh", "/lien-he", "/gioi-thieu", "/thu-vien",
    "/tap-chi", "/hoc-bong", "/ky-tuc-xa",
]

EDU_SUBDOMAINS_TOP10 = UNIVERSITIES[:10]
EDU_SUBDOMAIN_PREFIXES = ["daa", "courses", "student", "portal", "library", "elearning"]
EDU_SUBDOMAIN_PATHS = ["/", "/tin-tuc", "/dang-ky", "/lich-hoc", "/thong-bao"]

GOV_DOMAINS = [
    "mof.gov.vn", "moh.gov.vn", "moet.gov.vn", "mic.gov.vn", "mpi.gov.vn",
    "mt.gov.vn", "molisa.gov.vn", "mard.gov.vn", "moit.gov.vn", "monre.gov.vn",
    "mofa.gov.vn", "moj.gov.vn", "moha.gov.vn", "sbv.gov.vn", "chinhphu.vn",
]

GOV_PATHS = [
    "/", "/van-ban", "/van-ban-phap-luat", "/thong-bao", "/tin-tuc",
    "/tin-tuc-su-kien", "/co-cau-to-chuc", "/lich-su-hinh-thanh", "/lien-he",
    "/gioi-thieu", "/hoi-dap", "/thu-tuc-hanh-chinh", "/chien-luoc-quy-hoach",
    "/thong-tin-tuyen-truyen", "/lich-cong-tac", "/cong-khai-ngan-sach",
    "/thong-ke-bao-cao", "/du-an", "/hop-tac-quoc-te", "/chinh-sach",
]

BANKS = [
    "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "bidv.com.vn",
    "agribank.com.vn", "vietinbank.vn", "acb.com.vn", "tpb.vn",
    "sacombank.com.vn", "vpbank.com.vn",
]

BANK_PATHS = [
    "/", "/ca-nhan", "/doanh-nghiep", "/lai-suat", "/ty-gia", "/chi-nhanh-atm",
    "/the-tin-dung", "/the-ghi-no", "/vay-tien", "/tiet-kiem", "/chuyen-tien",
    "/tin-tuc", "/tuyen-dung", "/lien-he", "/gioi-thieu",
]

ECOMMERCE = [
    ("shopee.vn", ["https://shopee.vn/sitemap.xml"]),
    ("tiki.vn", ["https://tiki.vn/sitemap.xml", "https://tiki.vn/robots.txt"]),
    ("lazada.vn", ["https://www.lazada.vn/sitemap.xml"]),
    ("sendo.vn", ["https://www.sendo.vn/sitemap.xml"]),
    ("fptshop.com.vn", ["https://fptshop.com.vn/sitemap.xml"]),
    ("thegioididong.com", ["https://www.thegioididong.com/sitemap.xml"]),
    ("dienmayxanh.com", ["https://www.dienmayxanh.com/sitemap.xml"]),
    ("cellphones.com.vn", ["https://cellphones.com.vn/sitemap.xml"]),
    ("nguyenkim.com", ["https://www.nguyenkim.com/sitemap.xml"]),
    ("hoanghamobile.com", ["https://hoanghamobile.com/sitemap.xml"]),
]

ECOMMERCE_FALLBACK_PATHS = [
    "/", "/khuyen-mai", "/flash-sale", "/tin-tuc", "/lien-he",
    "/chinh-sach-bao-mat", "/dieu-khoan-su-dung", "/dien-thoai", "/laptop",
    "/may-tinh-bang", "/phu-kien-dien-thoai", "/tai-nghe", "/loa-bluetooth",
    "/dong-ho-thong-minh", "/tivi", "/tu-lanh", "/may-giat", "/may-lanh",
    "/dien-gia-dung", "/may-anh", "/may-quay", "/game-console",
    "/o-cung-ssd", "/man-hinh", "/ban-phim-chuot", "/router-wifi",
    "/camera-an-ninh", "/may-in", "/may-chieu", "/thiet-bi-mang",
    "/dong-ho-thoi-trang", "/dong-ho-deo-tay", "/sieu-thi-online",
    "/thuong-hieu/apple", "/thuong-hieu/samsung", "/thuong-hieu/xiaomi",
    "/thuong-hieu/oppo", "/thuong-hieu/vivo", "/thuong-hieu/realme",
    "/thuong-hieu/asus", "/thuong-hieu/acer", "/thuong-hieu/dell",
    "/thuong-hieu/hp", "/thuong-hieu/lenovo", "/thuong-hieu/lg",
    "/thuong-hieu/sony", "/thuong-hieu/panasonic", "/thuong-hieu/sharp",
    "/giam-gia-100k", "/giam-gia-200k", "/tra-gop", "/giao-hang-nhanh",
]
TARGET_ECOMMERCE_PER_SITE = 50


def fetch(url: str) -> bytes | None:
    try:
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "application/xml, text/xml, */*"},
        )
        if r.status_code >= 400:
            return None
        content = r.content
        if url.endswith(".gz") or content[:2] == b"\x1f\x8b":
            try:
                content = gzip.decompress(content)
            except OSError:
                pass
        ctype = (r.headers.get("content-type") or "").lower()
        stripped = content.lstrip()[:200].lower()
        if (b"<html" in stripped or b"<!doctype html" in stripped) and "xml" not in ctype:
            return None
        return content
    except requests.RequestException:
        return None


def parse_locs(xml_bytes: bytes) -> tuple[list[str], list[str]]:
    sitemaps: list[str] = []
    pages: list[str] = []
    try:
        root = ET.fromstring(xml_bytes)
        tag = root.tag.lower()
        if tag.endswith("sitemapindex"):
            for sm in root.findall("sm:sitemap", NS):
                loc = sm.find("sm:loc", NS)
                if loc is not None and loc.text:
                    sitemaps.append(loc.text.strip())
        elif tag.endswith("urlset"):
            for u in root.findall("sm:url", NS):
                loc = u.find("sm:loc", NS)
                if loc is not None and loc.text:
                    pages.append(loc.text.strip())
    except ET.ParseError:
        for txt in LOC_RE.findall(xml_bytes.decode("utf-8", errors="replace")):
            txt = txt.strip()
            if txt.endswith(".xml") or txt.endswith(".xml.gz"):
                sitemaps.append(txt)
            elif txt.startswith("http"):
                pages.append(txt)
    return sitemaps, pages


def crawl_ecommerce(site_name: str, candidates: list[str], target: int) -> tuple[list[str], str]:
    for sm_url in candidates:
        if sm_url.endswith("robots.txt"):
            continue
        xml_bytes = fetch(sm_url)
        time.sleep(SLEEP_BETWEEN_REQUESTS)
        if xml_bytes is None:
            continue
        children, pages = parse_locs(xml_bytes)
        collected = list(pages)
        for child in children:
            if len(collected) >= target:
                break
            child_bytes = fetch(child)
            time.sleep(SLEEP_BETWEEN_REQUESTS)
            if child_bytes is None:
                continue
            _, child_pages = parse_locs(child_bytes)
            collected.extend(child_pages)
        if collected:
            return collected[:target], "sitemap"
    pages = [f"https://{site_name}{p}" for p in ECOMMERCE_FALLBACK_PATHS[:target]]
    return pages, "template"


def build_edu() -> list[str]:
    urls: list[str] = []
    for dom in UNIVERSITIES:
        for p in EDU_PATHS:
            urls.append(f"https://{dom}{p}")
    return urls


def build_edu_subdomains() -> list[str]:
    urls: list[str] = []
    for dom in EDU_SUBDOMAINS_TOP10:
        for sub in EDU_SUBDOMAIN_PREFIXES:
            for p in EDU_SUBDOMAIN_PATHS:
                urls.append(f"https://{sub}.{dom}{p}")
    return urls


def build_gov() -> list[str]:
    urls: list[str] = []
    for dom in GOV_DOMAINS:
        for p in GOV_PATHS:
            urls.append(f"https://{dom}{p}")
    return urls


def build_banks() -> list[str]:
    urls: list[str] = []
    for dom in BANKS:
        for p in BANK_PATHS:
            urls.append(f"https://{dom}{p}")
    return urls


def main() -> int:
    print("=" * 70)
    print("  BUILD VN BENIGN MANUAL DATASET")
    print("=" * 70)

    category_counts: list[tuple[str, int, str]] = []

    edu_urls = build_edu()
    category_counts.append(("edu (main)", len(edu_urls), "template"))
    print(f"  edu (main):       {len(edu_urls):>5}")

    edu_sub_urls = build_edu_subdomains()
    category_counts.append(("edu (subdomain)", len(edu_sub_urls), "template"))
    print(f"  edu (subdomain):  {len(edu_sub_urls):>5}")

    gov_urls = build_gov()
    category_counts.append(("gov", len(gov_urls), "template"))
    print(f"  gov:              {len(gov_urls):>5}")

    bank_urls = build_banks()
    category_counts.append(("banking", len(bank_urls), "template"))
    print(f"  banking:          {len(bank_urls):>5}")

    print("\n  Attempting e-commerce sitemap crawl ...")
    ecom_urls: list[str] = []
    ecom_breakdown: list[tuple[str, int, str]] = []
    for site_name, candidates in ECOMMERCE:
        urls, source = crawl_ecommerce(site_name, candidates, TARGET_ECOMMERCE_PER_SITE)
        ecom_urls.extend(urls)
        ecom_breakdown.append((site_name, len(urls), source))
        print(f"    {site_name:<22} {len(urls):>3} URL  ({source})")
    category_counts.append(("ecommerce", len(ecom_urls), "mixed"))

    all_urls = edu_urls + edu_sub_urls + gov_urls + bank_urls + ecom_urls

    seen: set[str] = set()
    deduped: list[str] = []
    for u in all_urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    print("\n" + "-" * 70)
    print(f"  Total before dedup: {len(all_urls)}")
    print(f"  Total after  dedup: {len(deduped)}")
    print("-" * 70)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        for u in deduped:
            w.writerow([u, 0])

    print(f"\n[OK] Saved {len(deduped)} URL(s) to '{OUTPUT_PATH}'")

    print("\n  SUMMARY (category, count, source):")
    for cat, cnt, src in category_counts:
        print(f"    {cat:<20} {cnt:>5}  {src}")
    print("\n  E-COMMERCE BREAKDOWN:")
    for site, cnt, src in ecom_breakdown:
        print(f"    {site:<22} {cnt:>5}  {src}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
