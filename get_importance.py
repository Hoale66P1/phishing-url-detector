import joblib

print("=" * 60)
print("FEATURE IMPORTANCE — Model v4")
print("=" * 60)

model = joblib.load("model/phishing_model_v4.pkl")
feature_names = joblib.load("model/feature_names_v4.pkl")

importance = list(zip(feature_names, model.feature_importances_))
importance.sort(key=lambda x: x[1], reverse=True)

for i, (name, imp) in enumerate(importance, 1):
    print(f"{i:2d}. {name:30s} {imp:.4f}  ({imp*100:.2f}%)")

print()
print("Sum check:", sum(imp for _, imp in importance))
