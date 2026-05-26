import csv
import os
import random
import sys

random.seed(42)

OUTPUT_PATH = os.path.join("data", "vn_ecommerce_paths.csv")
DOMAINS = [
    "shopee.vn", "tiki.vn", "lazada.vn", "sendo.vn",
    "fptshop.com.vn", "thegioididong.com", "dienmayxanh.com", "cellphones.com.vn",
]

PRODUCT_IDS = [str(random.randint(10**5, 10**9 - 1)) for _ in range(100)]

CATEGORY_SLUGS = [
    "tv", "pc", "ac", "fan", "loa", "dt", "lt", "tb", "pk",
    "phones", "laptops", "tablets", "accessories", "tv-audio", "appliances",
    "cameras", "gaming", "wearables", "headphones", "speakers",
    "fashion", "beauty", "books", "toys", "home", "garden", "kitchen",
    "sports", "fitness", "outdoor", "auto", "moto", "office",
    "electronics", "smart-home", "networking", "storage", "monitors",
    "keyboards", "mice", "printers", "scanners", "projectors", "drones",
    "watches", "jewelry", "bags", "shoes", "groceries", "pharmacy",
]
assert len(CATEGORY_SLUGS) == 50

SUBCATEGORY_SLUGS = [
    "iphone", "samsung", "xiaomi", "oppo", "vivo", "realme", "asus", "acer",
    "dell", "hp", "lenovo", "msi", "apple", "lg", "sony", "panasonic", "sharp",
    "philips", "tcl", "casper", "electrolux", "toshiba", "hitachi",
    "canon", "nikon", "fujifilm", "gopro", "dji", "garmin", "fitbit",
    "logitech", "razer", "corsair", "kingston", "western-digital", "seagate",
    "intel", "amd", "nvidia", "qualcomm", "mediatek", "sandisk",
    "bose", "jbl", "harman-kardon", "sennheiser", "audio-technica", "beats",
    "anker", "baseus",
]
assert len(SUBCATEGORY_SLUGS) == 50

SEARCH_KEYWORDS = [
    "iphone-15", "samsung-galaxy-s24", "macbook-air-m2", "laptop-gaming",
    "dien-thoai", "may-anh", "tai-nghe", "loa-bluetooth", "tu-lanh",
    "may-giat", "may-lanh", "tivi-4k", "ban-phim-co", "chuot-gaming",
    "monitor-144hz", "ssd-1tb", "ram-32gb", "router-wifi-6",
    "iphone+15+pro+max", "samsung+s24+ultra", "rtx+4070", "rtx+4080",
    "airpods+pro", "watch+ultra", "xiaomi+13t", "oppo+find+x7",
    "vivo+x100", "realme+gt", "asus+rog", "msi+raider",
    "dell+xps+13", "hp+pavilion", "lenovo+thinkpad", "acer+predator",
    "canon+r6", "sony+a7iv", "gopro+hero+12", "dji+mavic+3",
    "tu-lanh-side-by-side", "may-giat-cua-truoc", "tivi-oled-55-inch",
    "ban-la-hoi-nuoc", "noi-com-dien", "may-loc-nuoc", "may-hut-bui",
    "robot-hut-bui", "may-pha-ca-phe", "noi-chien-khong-dau",
    "may-xay-sinh-to", "lo-vi-song",
]
assert len(SEARCH_KEYWORDS) == 50

HYPHEN_SLUGS = [
    "dien-thoai-iphone-15-pro-max-256gb",
    "dien-thoai-samsung-galaxy-s24-ultra-256gb",
    "laptop-asus-rog-strix-g15",
    "laptop-msi-raider-ge78-hx",
    "may-anh-canon-eos-r6-mark-ii",
    "tai-nghe-apple-airpods-pro-2",
    "loa-bluetooth-jbl-charge-5",
    "tu-lanh-samsung-side-by-side-617l",
    "may-giat-lg-cua-truoc-10kg",
    "may-lanh-daikin-inverter-1-hp",
    "tivi-sony-bravia-oled-55-inch",
    "smart-watch-apple-series-9-45mm",
    "ban-phim-co-logitech-g-pro-x",
    "chuot-gaming-razer-deathadder-v3",
    "monitor-asus-rog-swift-pg279qm",
    "ssd-samsung-980-pro-1tb-nvme",
    "ram-corsair-vengeance-32gb-ddr5",
    "router-asus-rt-ax88u-wifi-6",
    "may-tinh-bang-ipad-air-m2-128gb",
    "dong-ho-thong-minh-galaxy-watch-6",
    "phu-kien-iphone-cap-sac-type-c",
    "may-pha-ca-phe-delonghi-magnifica",
    "noi-chien-khong-dau-philips-7-lit",
    "tu-lanh-mini-electrolux-92-lit",
    "may-loc-khong-khi-xiaomi-4-pro",
    "robot-hut-bui-roborock-s8-pro-ultra",
    "may-xay-sinh-to-philips-hr2095",
    "noi-com-dien-cuckoo-1-8-lit",
    "lo-vi-song-sharp-23-lit",
    "ban-la-hoi-nuoc-tefal-pro-express",
    "may-say-toc-dyson-supersonic",
    "may-cao-rau-braun-series-9",
    "ban-chai-dien-oral-b-pro-1500",
    "may-massage-co-vai-omron",
    "can-suc-khoe-xiaomi-mi-body-composition",
    "may-do-huyet-ap-omron-hem-7156",
    "may-do-duong-huyet-accu-chek-active",
    "may-tao-oxy-philips-everflo",
    "xe-day-em-be-combi-mechacal-handy",
    "ghe-an-cho-be-fisher-price",
    "ghe-massage-okia-king-pro",
    "may-chay-bo-dien-bowflex-tt10",
    "xe-dap-tap-the-duc-pro-form",
    "ban-bong-ban-butterfly-octet",
    "cu-ta-chrome-20kg-cap-set",
    "vot-cau-long-yonex-astrox-99",
    "giay-the-thao-nike-air-zoom",
    "balo-laptop-targus-15-6-inch",
    "vali-keo-american-tourister",
    "tui-deo-cheo-da-bo-cao-cap",
    "kinh-mat-rayban-aviator-classic",
    "dong-ho-deo-tay-casio-edifice",
    "may-cat-co-stihl-fs-55",
    "may-khoan-bosch-gsr-18v",
    "may-han-jasic-tig-200",
    "sung-ban-phun-son-3m-accuspray",
    "may-bom-nuoc-mini-shimizu",
    "may-loc-nuoc-karofi-10-cap",
    "binh-nuoc-nong-ariston-30-lit",
    "bep-tu-doi-bosch-pid675dc1e",
    "may-rua-bat-bosch-12-bo",
    "may-hut-mui-hafele-90cm",
    "noi-com-tach-duong-cuckoo",
    "may-lam-sua-chua-yogurt-tefal",
    "may-lam-sua-hat-elmich-1500w",
    "may-ep-trai-cay-cham-panasonic",
    "may-say-quan-ao-electrolux-9kg",
    "xe-may-honda-air-blade-160",
    "xe-may-yamaha-grande-125",
    "xe-may-vespa-primavera-150",
    "xe-dap-dia-hinh-giant-talon",
    "xe-dap-the-thao-trinx-tempo",
    "mu-bao-hiem-andes-3s-fullface",
    "lop-xe-michelin-power-pure",
    "dau-nhot-motul-7100-10w40",
    "dau-nhot-castrol-power1-racing",
    "phu-kien-camera-go-pro-12",
    "may-ghi-am-sony-icd-px470",
    "may-chieu-mini-xgimi-mogo-2",
    "may-quay-phim-sony-fdr-ax700",
    "the-nho-sandisk-extreme-pro-256gb",
    "o-cung-di-dong-wd-my-passport-2tb",
    "case-may-tinh-corsair-icue-5000d",
    "nguon-may-tinh-corsair-rm1000x",
    "tan-nhiet-cpu-noctua-nh-d15",
    "tan-nhiet-cpu-deepcool-ak620",
    "card-do-hoa-rtx-4070-ti-super",
    "card-do-hoa-rtx-4080-super",
    "main-asus-rog-strix-b650e-e",
    "main-msi-mpg-z790-edge-wifi",
    "cpu-intel-core-i7-14700k",
    "cpu-amd-ryzen-9-7950x3d",
    "ban-phim-co-keychron-q1-pro",
    "chuot-logitech-mx-master-3s",
    "tai-nghe-sony-wh-1000xm5",
    "tai-nghe-bose-quietcomfort-ultra",
    "loa-bluetooth-bose-soundlink-flex",
    "loa-sony-srs-xb43-extra-bass",
    "loa-jbl-flip-6-portable",
    "may-anh-fujifilm-x-t5-body",
    "may-anh-leica-q3-full-frame",
    "may-anh-nikon-zfc-kit-16-50",
]
HYPHEN_SLUGS = HYPHEN_SLUGS[:100]
assert len(HYPHEN_SLUGS) == 100

SINGLE_SLUGS = [
    "electronics", "phones", "laptops", "tablets", "cameras",
    "watches", "headphones", "speakers", "tv", "audio",
    "appliances", "fridges", "washers", "dryers", "stoves",
    "ovens", "microwaves", "blenders", "toasters", "kettles",
    "fans", "heaters", "ac", "humidifiers", "purifiers",
    "vacuums", "irons", "cookers", "fryers", "grills",
    "gaming", "consoles", "controllers", "keyboards", "mice",
    "monitors", "printers", "scanners", "projectors", "routers",
    "drives", "storage", "memory", "cards", "cables",
    "chargers", "batteries", "adapters", "cases", "covers",
    "screens", "protectors", "stands", "mounts", "tripods",
    "lenses", "filters", "flashes", "lighting", "studios",
    "drones", "gimbals", "stabilizers", "microphones", "recorders",
    "fashion", "clothing", "shoes", "bags", "wallets",
    "watches", "jewelry", "sunglasses", "accessories", "perfumes",
    "beauty", "skincare", "haircare", "makeup", "fragrances",
    "groceries", "snacks", "drinks", "supplements", "vitamins",
    "books", "magazines", "stationery", "office", "school",
    "toys", "games", "puzzles", "lego", "dolls",
    "sports", "fitness", "outdoor", "camping", "fishing",
]
assert len(SINGLE_SLUGS) == 100


def gen_for_domain(d: str) -> list[str]:
    urls: list[str] = []
    urls.append(f"https://{d}/products")
    for pid in PRODUCT_IDS:
        urls.append(f"https://{d}/products/{pid}")
    for pid in PRODUCT_IDS:
        urls.append(f"https://{d}/p/{pid}")
    for slug in CATEGORY_SLUGS:
        urls.append(f"https://{d}/category/{slug}")
    for slug, sub in zip(CATEGORY_SLUGS, SUBCATEGORY_SLUGS):
        urls.append(f"https://{d}/category/{slug}/{sub}")
    for kw in SEARCH_KEYWORDS:
        urls.append(f"https://{d}/search?q={kw}")
    for static in ("user/orders", "cart", "checkout"):
        urls.append(f"https://{d}/{static}")
    for slug, sub in zip(CATEGORY_SLUGS, SUBCATEGORY_SLUGS):
        urls.append(f"https://{d}/vn-vn/{slug}/{sub}")
    for slug in HYPHEN_SLUGS:
        urls.append(f"https://{d}/{slug}.html")
    for slug in SINGLE_SLUGS:
        urls.append(f"https://{d}/{slug}")
    return urls


def main() -> int:
    print("=" * 70)
    print("  VN E-COMMERCE PATH TEMPLATE GENERATOR")
    print("=" * 70)

    all_urls: list[str] = []
    per_domain: list[tuple[str, int]] = []
    for d in DOMAINS:
        urls = gen_for_domain(d)
        per_domain.append((d, len(urls)))
        all_urls.extend(urls)

    seen: set[str] = set()
    deduped: list[str] = []
    for u in all_urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        for u in deduped:
            w.writerow([u, 0])

    print(f"\n  Domains: {len(DOMAINS)}")
    for d, n in per_domain:
        print(f"    {d:<24} {n:>5} URL")
    print(f"\n  Total before dedup: {len(all_urls):,}")
    print(f"  Total after  dedup: {len(deduped):,}")
    print(f"  Saved -> '{OUTPUT_PATH}'")

    print("\n  Sample 10 URLs (random):")
    for u in random.sample(deduped, 10):
        print(f"    {u}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
