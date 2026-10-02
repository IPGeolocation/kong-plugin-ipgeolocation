#!/usr/bin/env python3
"""Writes benchmark address lists drawn from networks present in a database.

usage: bench/sample-ips.py <database.mmdb> <out-prefix> [count=20000] [seed=1]
Produces <out-prefix>.v4.txt and <out-prefix>.v6.txt (needs python maxminddb).
"""
import ipaddress, random, sys
import maxminddb

db, prefix = sys.argv[1], sys.argv[2]
count = int(sys.argv[3]) if len(sys.argv) > 3 else 20000
rnd = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
r = maxminddb.open_database(db, maxminddb.MODE_MMAP)
v4, v6 = [], []
for net, _ in r:
    lst = v4 if net.version == 4 else v6
    if len(lst) < count and rnd.random() < 0.05:
        off = rnd.randrange(net.num_addresses) if net.num_addresses > 1 else 0
        lst.append(str(ipaddress.ip_address(int(net.network_address) + off)))
    if len(v4) >= count and len(v6) >= count:
        break
for name, lst in (("v4", v4), ("v6", v6)):
    with open(f"{prefix}.{name}.txt", "w") as f:
        f.write("\n".join(lst) + "\n")
    print(name, len(lst))
