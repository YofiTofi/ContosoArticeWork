import pandas as pd
import data

# TODO 1. Find a way to pop first row, when passing copy_df to subsequent tests
# TODO 2. Find a way to reliably compare times

scheme ={
    "Ad": lambda user_df: user_df["DestHostname"][0] in data.known_ad_plaforms,
    "Redirect": lambda user_df: user_df["AccessType"][0] == "Redirection",
    "DifferentSite": lambda priv_website, curr_website: priv_website != curr_website,
    "Download": lambda user_df: int(user_df["TrafficBytes"][0]) >= 30720,
}
detection_rules = {
    "Malvertising": ["Ad", "Redirect", "Redirect", "Download"]
}


df = pd.read_csv('./Capture.csv')
unique_local_users = df["SourceUser"].unique()
df["Time"] = pd.to_datetime(df["Time"])
df.sort_values(by=["Time"], inplace=True)
for user in unique_local_users:
    user_df = df.loc[df["SourceUser"] == user]
    for rule in detection_rules.values():
        copy_df = user_df
        detection_flag = True
        for subrule in rule:
            print(f"Testing {subrule}")
            print(copy_df)
            if scheme[subrule](copy_df):
                print(f"{subrule} detected")
                copy_df = copy_df.iloc[1:]
                print(f"This is accesstype: {copy_df['AccessType'][1]}")
            else:
                detection_flag = False
                print(f"{subrule} not detected")
        if detection_flag:
            print(f"{rule} is detected!")