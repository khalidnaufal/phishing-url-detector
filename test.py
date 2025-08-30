import pandas as pd

df = pd.read_csv("data/phishing.csv")
print("Cols:", list(df.columns)[:10], "...")  # peek first 10 names
for cand in ["Result","Label","Class","CLASS","class","status","target","Target"]:
    if cand in df.columns:
        print("Found label column:", cand, "=>", df[cand].value_counts().to_dict())
