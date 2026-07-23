import pandas as pd

df1 = pd.read_csv("data.csv")
df2 = pd.read_csv("data_bengin.csv")

df3 = pd.concat([df1,df2],ignore_index=True)

df3.to_csv("now_final.csv",index=False)
print("Saved sucessfully")