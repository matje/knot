#!/usr/bin/env python3

'''RRL module functionality test'''

import dns.exception
import dns.message
import dns.query
import time

from dnstest.test import Test
from dnstest.module import ModRRL
from dnstest.utils import *

t = Test(stress=False)
ModRRL.check()
knot = t.server("knot")
# Initialize server configuration
local_zone = t.zone("test", storage=".", file_name="test.local_zone")
remote_zone1 = t.zone("test", storage=".", file_name="test.remote_zone")
remote_zone2 = t.zone("example.com.")

t.link(local_zone, knot)
t.link(remote_zone1, knot)
t.link(remote_zone2, knot)

def send_queries(server, run_time=1.0, query_time=0.05):
    """
    Send UDP queries to the server for certain time and get replies statistics.
    """
    replied, truncated, dropped = 0, 0, 0
    start = time.time()
    while time.time() < start + run_time:
        try:
            query = dns.message.make_query("example.com", "SOA", want_dnssec=True)
            response = dns.query.udp(query, server.addr, port=server.port, timeout=query_time)
        except dns.exception.Timeout:
            response = None

        if response is None:
            dropped += 1
        elif response.flags & dns.flags.TC:
            truncated += 1
        else:
            replied += 1

    return dict(replied=replied, truncated=truncated, dropped=dropped)

def rrl_result(name, stats, success):
    detail_log("RRL %s" % name)
    detail_log(", ".join(["%s %d" % (s, stats[s]) for s in ["replied", "truncated", "dropped"]]))
    if success:
        detail_log("success")
    else:
        detail_log("error")
        set_err("RRL ERROR")


t.start()
knot.zones_wait(local_zone, remote_zone1, remote_zone2)
t.sleep(1)

#
# We cannot send queries in parallel. And we have to give the server some time
# to respond, especially under valgrind. Therefore we have to be tolerant when
# counting responses when packets are being dropped.
#

stats = send_queries(knot)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("RRL disabled", stats, ok)

knot.add_module(None, ModRRL(5, None, None, None))
knot.gen_confile()
knot.reload()
stats = send_queries(knot)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("RRL enabled, all slips", stats, ok)
time.sleep(5)

knot.add_module(None, ModRRL(None, None, 0, None))
knot.gen_confile()
knot.reload()
stats = send_queries(knot)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] == 0 and stats["dropped"] >= 5
rrl_result("RRL enabled, no slips", stats, ok)

knot.add_module(None, ModRRL(None, None, 2, None))
knot.gen_confile()
knot.reload()
stats = send_queries(knot)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 5 and stats["dropped"] >= 5
rrl_result("RRL enabled, 50% slips", stats, ok)

knot.add_module(None, ModRRL(None, None, None, knot.addr))
knot.gen_confile()
knot.reload()
stats = send_queries(knot)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("RRL enabled, whitelist effective", stats, ok)

t.end()
