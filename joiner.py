import pandas as pd

df_q = pd.read_csv("./data/qakbot/data1.csv")
df_b = pd.read_csv("./data/bengin/data1.csv")
df_et = pd.read_csv("./data/emotet_trickbot/data1.csv")
modify_id_1 = {
    1:17,
    2:18,
    3:19,
    4:20,
    5:21,
    6:22
}
modify_id_2 = {
    1:23,
    2:24,
    3:25,
    4:26,
    5:27
}

#df["sample_hash"] = df["pcap_id"].map(add_sample_hash)
#df['label'] = "bengin"
df_q["pcap_id"] = df_q["pcap_id"].map(modify_id_1)
df_b["pcap_id"] = df_b["pcap_id"].map(modify_id_2)


df3 = pd.concat([df_et,df_q,df_b],ignore_index=True)

df3.to_csv("./data/now_final_3malware.csv",index=False)
print("Saved sucessfully")