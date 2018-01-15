# -*- coding: utf-8 -*-

try:
    from dns import resolver
    HAVE_DNSPYTHON=True
except ImportError:
    resolver = None
    HAVE_DNSPYTHON=False

try:
    import DNS
    HAVE_PYDNS=True
    DNS.DiscoverNameServers()
except ImportError:
    DNS = None
    HAVE_PYDNS=False

HAVE_DNS = HAVE_DNSPYTHON or HAVE_PYDNS


def lookup(hostname, qtype='A'):
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
            mxrequest = resolver.query(domain, 'MX')
            for rec in mxrequest:
                mxrecs.append(rec.to_text())
            mxrecs.sort() #automatically sorts by priority
            return [x.split(None,1)[-1] for x in mxrecs]
        
        elif HAVE_PYDNS:
            mxrecs=[]
            mxrequest = DNS.mxlookup(domain)
            for dataset in mxrequest:
                if type(dataset) == tuple:
                    mxrecs.append(dataset)
                    
            mxrecs.sort() #automatically sorts by priority
            return [x[1] for x in mxrecs]
        
    except Exception:
        return None
    
    return None



def revlookup(ip):
    a = ip.split('.')
    a.reverse()
    revip = '.'.join(a)+'.in-addr.arpa'
    return lookup(revip, qtype='PTR')


