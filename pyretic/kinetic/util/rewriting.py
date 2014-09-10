from pyretic.lib.corelib import *
from pyretic.lib.std import *

def getMACFromIP(ip):
    ip_str = str(ip)
    part = ip_str.split('.')[3]
    mac_str = "00:00:00:00:00:" + "{:02x}".format(int(part))
    return mac_str

def rewriteDstIPAndMAC_Public(client_ips, public_ip_str, target_ip_str):
    target_ips = [IP(target_ip_str)]*len(client_ips)
    d = zip(client_ips, target_ips)
    return intersection([subsp(c,r,IP(public_ip_str)) for c,r in d])

def rewriteDstIPAndMAC(client_ips, target_ip_str):
    target_ips = [IP(target_ip_str)]*len(client_ips)
    d = zip(client_ips, target_ips)
    pol = None
    for ip in client_ips:
        if pol == None:
            pol = intersection([subs(c,r, IP(ip)) for c,r in d])
        else:
            pol = pol + intersection([subs(c,r, IP(ip)) for c,r in d])
    return pol


# subroutine of rewrite()
def subs(c,r,p):
    c_to_p = match(srcip=c,dstip=p)
    r_to_c = match(srcip=r,dstip=c)
    rewrite_mac_policy = if_(match(dstip=IP(r),ethtype=2048),
                                     modify(dstmac=MAC(getMACFromIP(r))),if_(match(ethtype=2054),passthrough,drop))

    return (((c_to_p >> modify(dstip=r))+(r_to_c >> modify(srcip=p))+(~r_to_c >> ~c_to_p))) >> rewrite_mac_policy


# subroutine of rewrite()
def subsp(c,r,p):
    c_to_p = match(srcip=c,dstip=p)
    r_to_c = match(srcip=r,dstip=c)
    rewrite_mac_policy = if_(match(dstip=IP(r),ethtype=2048),
                                     modify(dstmac=MAC(getMACFromIP(r))),passthrough)

    return (((c_to_p >> modify(dstip=r))+(r_to_c >> modify(srcip=p))+(~r_to_c >> ~c_to_p))) >> rewrite_mac_policy

