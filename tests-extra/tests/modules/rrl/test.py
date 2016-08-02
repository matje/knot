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
knot_glob = t.server("knot")
# Initialize server configuration
zones = t.zone_rnd(3, dnssec=False, records=1)

t.link(zones, knot)
t.link(zones, knot_glob)

def send_queries(server, name, run_time=1.0, query_time=0.05):
    """
    Send UDP queries to the server for certain time and get replies statistics.
    """
    replied, truncated, dropped = 0, 0, 0
    start = time.time()
    while time.time() < start + run_time:
        try:
            query = dns.message.make_query(name, "SOA", want_dnssec=True)
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

knot.zones_wait(zones)
knot_glob.zones_wait(zones)
t.sleep(1)

#
# We cannot send queries in parallel. And we have to give the server some time
# to respond, especially under valgrind. Therefore we have to be tolerant when
# counting responses when packets are being dropped.
#

# RRL disabled for both
stats = send_queries(knot, zones[0].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("disabled", stats, ok)
time.sleep(2)

stats = send_queries(knot_glob, zones[0].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("disabled", stats, ok)

# RRL enabled globaly
knot_glob.add_module(None, ModRRL(5, None, None, None))
knot_glob.gen_confile()
knot_glob.reload()

stats = send_queries(knot_glob, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("enabled globaly for zone 1, all slips", stats, ok)
time.sleep(2)

stats = send_queries(knot_glob, zones[1].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("enabled globaly for zone 2, all slips", stats, ok)
time.sleep(2)

# RRL enabled globaly, 0 slips
knot_glob.clear_modules(None)
knot_glob.add_module(None, ModRRL(5, None, 0, None))
knot_glob.gen_confile()
knot_glob.reload()

stats = send_queries(knot_glob, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] == 0 and stats["dropped"] >= 5
rrl_result("enabled globaly, zone 1, zero slips", stats, ok)
time.sleep(2)

stats = send_queries(knot_glob, zones[1].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] == 0 and stats["dropped"] >= 5
rrl_result("enabled globaly, zone 2, zero slips", stats, ok)
time.sleep(2)

# RLL whitelist enabled globaly
knot_glob.clear_modules(None)
knot_glob.add_module(None, ModRRL(5, None, 2, knot_glob.addr))
knot_glob.gen_confile()
knot_glob.reload()

stats = send_queries(knot_glob, zones[0].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("enabled globaly, zone 1, whitelist effective", stats, ok)

stats = send_queries(knot_glob, zones[1].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("enabled globaly, zone 2, whitelist effective", stats, ok)

# Tests for per zone rrl, not supported atm.
'''
# RLL enabled for zone1
knot.add_module(zones[0], ModRRL(5, None, None, None))
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("enabled for zone 1, all slips", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("disabled for zone 2", stats, ok)
time.sleep(2)

# RLL enabled for zone1, 0 slips
knot.clear_modules(zones[0])
knot.add_module(zones[0], ModRRL(5, None, 0, None))
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] == 0 and stats["dropped"] >= 5
rrl_result("enabled for zone 1, 0 slips", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("disabled for zone 2", stats, ok)
time.sleep(2)

# RLL enabled globaly, whitelist for zone1
knot.clear_modules(zones[0])
knot.add_module(zones[0], ModRRL(5, None, None, knot.addr))
knot.add_module(zones[1], ModRRL(5, None, None, None))
knot.clear_modules(None)
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("enabled, whitelist effective for zone 1", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("enabled for zone 2, zone 1 whitelist ineffective", stats, ok)
'''
t.end()
