import csv
import os

TRANCO_PATH = os.path.join("data", "tranco_full.csv")
OUT_PATH = os.path.join("data", "whitelist_vn.txt")
TRANCO_VN_TOP_N = 60

MUST_INCLUDE = [
    "vnexpress.net", "tuoitre.vn", "thanhnien.vn", "dantri.com.vn",
    "vietnamnet.vn", "cafef.vn", "kenh14.vn", "znews.vn", "tienphong.vn",
    "laodong.vn", "baomoi.com", "24h.com.vn",
    "shopee.vn", "tiki.vn", "lazada.vn", "sendo.vn",
    "fptshop.com.vn", "thegioididong.com", "dienmayxanh.com", "cellphones.com.vn",
    "uit.edu.vn", "hcmut.edu.vn", "hcmus.edu.vn", "vnu.edu.vn", "hust.edu.vn",
    "neu.edu.vn", "ftu.edu.vn", "ueh.edu.vn", "hcmute.edu.vn", "tdtu.edu.vn",
    "iuh.edu.vn", "hou.edu.vn", "ptit.edu.vn", "ctu.edu.vn", "hueuni.edu.vn",
    "udn.vn", "hnue.edu.vn", "duytan.edu.vn", "vlu.edu.vn", "tlu.edu.vn",
    "chinhphu.vn", "mof.gov.vn", "moh.gov.vn", "moet.gov.vn", "mic.gov.vn",
    "mpi.gov.vn", "moit.gov.vn", "molisa.gov.vn", "mard.gov.vn", "mt.gov.vn",
    "monre.gov.vn", "sbv.gov.vn", "vietnam.vn",
    "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "bidv.com.vn",
    "agribank.com.vn", "vietinbank.vn", "acb.com.vn", "tpb.vn",
    "sacombank.com.vn", "vpbank.com.vn",
]


def main() -> int:
    tranco_vn: list[tuple[int, str]] = []
    with open(TRANCO_PATH, "r", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) < 2:
                continue
            try:
                rank = int(row[0])
            except ValueError:
                continue
            dom = row[1].strip().lower()
            if dom.endswith(".vn"):
                tranco_vn.append((rank, dom))
                if len(tranco_vn) >= TRANCO_VN_TOP_N:
                    break

    tranco_domains = [d for _, d in tranco_vn]
    print(f"  Tranco .vn top {TRANCO_VN_TOP_N}: {len(tranco_domains)} domains")

    combined: set[str] = set(tranco_domains) | set(d.lower() for d in MUST_INCLUDE)
    sorted_domains = sorted(combined)

    print(f"  Manual augments: {len(MUST_INCLUDE)} domains")
    print(f"  Combined unique: {len(sorted_domains)} domains")

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("# Whitelist: domains pre-approved, bypass ML\n")
        f.write(f"# Source: Tranco top {TRANCO_VN_TOP_N} .vn + manual augments\n")
        f.write(f"# Total: {len(sorted_domains)} domains\n")
        for d in sorted_domains:
            f.write(d + "\n")

    print(f"  Saved -> '{OUT_PATH}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
