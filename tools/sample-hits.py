#!/usr/bin/env python3
"""Prints JSON {database path: [addresses]} with up to N addresses that have
records in each database under a directory (input for sample-matrix.lua)."""
import glob, json, sys
import maxminddb
root, n = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 400
out = {}
for p in sorted(glob.glob(root + "/**/*.mmdb", recursive=True)):
    r = maxminddb.open_database(p, maxminddb.MODE_MMAP)
    ips, step = [], 0
    for net, rec in r:
        step += 1
        if rec and step % 7 == 0:
            ips.append(str(net.network_address))
        if len(ips) >= n:
            break
    out[p] = ips
json.dump(out, sys.stdout)
