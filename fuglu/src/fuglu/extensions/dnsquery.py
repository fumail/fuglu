# -*- coding: utf-8 -*-
#   Copyright 2009-2018 Fumail Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
#
STATUS = "not loaded"

try:
    from dns import resolver
    HAVE_DNSPYTHON=True
    STATUS = "available"
except ImportError:
    resolver = None
    HAVE_DNSPYTHON=False

HAVE_PYDNS=False
if not HAVE_DNSPYTHON:
    try:
        import DNS
        HAVE_PYDNS=True
        DNS.DiscoverNameServers()
        STATUS = "available"
    except ImportError:
        DNS = None
        STATUS = "DNS not installed"

ENABLED = DNSQUERY_EXTENSION_ENABLED = HAVE_DNSPYTHON or HAVE_PYDNS



QTYPE_A = 'A'
QTYPE_MX = 'MX'
QTYPE_NS = 'NS'
QTYPE_TXT = 'TXT'
QTYPE_PTR = 'PTR'
QTYPE_CNAME = 'CNAME'
QTYPE_SPF = 'SPF'
QTYPE_SRV = 'SRV'
QTYPE_SOA = 'SOA'



def lookup(hostname, qtype=QTYPE_A):
    try:
        if HAVE_DNSPYTHON:
            arecs = []
            arequest = resolver.query(hostname, qtype)
            for rec in arequest:
                arecs.append(rec.to_text())
            return arecs

        elif HAVE_PYDNS:
            return DNS.dnslookup(hostname, qtype)

    except Exception:
        return None

    return None



def mxlookup(domain):
    try:
        if HAVE_DNSPYTHON:
            mxrecs = []
            mxrequest = resolver.query(domain, QTYPE_MX)
            for rec in mxrequest:
                mxrecs.append(rec.to_text())
            mxrecs.sort()  # automatically sorts by priority
            return [x.split(None, 1)[-1] for x in mxrecs]

        elif HAVE_PYDNS:
            mxrecs = []
            mxrequest = DNS.mxlookup(domain)
            for dataset in mxrequest:
                if type(dataset) == tuple:
                    mxrecs.append(dataset)

            mxrecs.sort()  # automatically sorts by priority
            return [x[1] for x in mxrecs]

    except Exception:
        return None

    return None



def revlookup(ip):
    a = ip.split('.')
    a.reverse()
    revip = '.'.join(a)+'.in-addr.arpa'
    return lookup(revip, qtype=QTYPE_PTR)
