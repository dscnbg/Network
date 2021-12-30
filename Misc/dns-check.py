import pandas as pd
from dns import reversename, resolver

df = pd.read_csv (r'C:\Temp\Git\Misc\Output\bbdns.txt')

max = len(df.index)
for x in range(0, max):
    ip = df['ip'][x]
    rev_name = reversename.from_address(ip)
    try:
        reversed_dns = str(resolver.query(rev_name,"PTR")[0])
    except Exception as e:
        print("No Record " + ip)
    else:
        print(reversed_dns)
