import pandas as pd
import sys
import os

os.environ["PYTHONIOENCODING"] = "utf-8"

FILE_1 = "data/dataset.csv"
FILE_2 = "data/Dataset01.csv"
OUTPUT = "data/dataset_combined.csv"

def main():
    print("=" * 60)
    print("  DATA VALIDATION & MERGING")
    print("=" * 60)

    df1 = pd.read_csv(FILE_1)
    df2 = pd.read_csv(FILE_2)

    for name, df in [(FILE_1, df1), (FILE_2, df2)]:
        print()
        print("-" * 60)
        print(f"  FILE: {name}")
        print("-" * 60)
        print(f"  Columns : {list(df.columns)}")
        print(f"  Dtypes  :")
        print(df.dtypes.to_string())
        print(f"  Samples : {len(df)}")
        if "type" in df.columns:
            print(f"  Label distribution:")
            print(df["type"].value_counts().to_string())
        print()
        print("  First 5 rows:")
        print(df.head().to_string())

    print()
    print("=" * 60)
    print("  SCHEMA COMPARISON")
    print("=" * 60)

    cols1 = list(df1.columns)
    cols2 = list(df2.columns)
    dtypes1 = df1.dtypes
    dtypes2 = df2.dtypes

    schema_match = True

    if cols1 != cols2:
        schema_match = False
        only_in_1 = set(cols1) - set(cols2)
        only_in_2 = set(cols2) - set(cols1)
        print("[MISMATCH] Column names differ!")
        if only_in_1:
            print(f"  Only in {FILE_1}: {only_in_1}")
        if only_in_2:
            print(f"  Only in {FILE_2}: {only_in_2}")
        common = set(cols1) & set(cols2)
        print(f"  Common columns: {common}")
        print()
        print("  Suggested mapping:")
        for c in only_in_2:
            print(f"    '{c}' in {FILE_2}  ->  ???")
    else:
        dtype_mismatches = []
        for col in cols1:
            if dtypes1[col] != dtypes2[col]:
                dtype_mismatches.append((col, dtypes1[col], dtypes2[col]))
        if dtype_mismatches:
            schema_match = False
            print("[MISMATCH] Dtype differences found:")
            for col, d1, d2 in dtype_mismatches:
                print(f"  Column '{col}': {d1} vs {d2}")

    if not schema_match:
        print()
        print("[STOP] Schema mismatch detected. Halting process.")
        sys.exit(1)

    print("[OK] Schema matches perfectly.")

    print()
    print("=" * 60)
    print("  MERGING DATASETS")
    print("=" * 60)

    total_before = len(df1) + len(df2)
    combined = pd.concat([df1, df2], ignore_index=True)
    print(f"  Total rows before dedup : {total_before}")

    url_col = None
    for c in combined.columns:
        if c.lower() == "url":
            url_col = c
            break

    if url_col:
        combined.drop_duplicates(subset=[url_col], inplace=True)
    else:
        print("  [WARN] No 'url' column found. Dropping full-row duplicates instead.")
        combined.drop_duplicates(inplace=True)

    print(f"  Total rows after dedup  : {len(combined)}")
    print(f"  Duplicates removed      : {total_before - len(combined)}")

    combined.to_csv(OUTPUT, index=False)
    print(f"  [SAVED] Combined dataset -> '{OUTPUT}'")

    print()
    print("=" * 60)
    print("  PHASE 1 COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
