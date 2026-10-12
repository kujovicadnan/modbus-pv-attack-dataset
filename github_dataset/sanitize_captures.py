"""Keep only traffic between the four documented test roles: Modbus/TCP (port 502),
ICMP between roles, and ARP between roles. Everything else (other devices, mDNS, DHCP,
DNS, IPv6, internet traffic) is dropped.
Usage: python sanitize_captures.py <input_dir> <output_dir>"""
import sys, glob, os, json
from scapy.all import rdpcap, Ether, ARP, IP, IPv6
from scapy.layers.inet import ICMP, TCP
from scapy.utils import PcapNgWriter

ROLES = {'192.168.178.1', '192.168.178.159', '192.168.178.181', '192.168.178.189'}
ROLE_MACS = {'aa:bb:cc:11:22:33', 'aa:bb:cc:44:55:66', 'aa:bb:cc:77:88:99', 'aa:bb:cc:aa:bb:cc',
             'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}
src, dst = sys.argv[1], sys.argv[2]
os.makedirs(dst, exist_ok=True)
stats = {}
for f in sorted(glob.glob(os.path.join(src, '*.pcapng'))):
    keep = []
    pk = rdpcap(f)
    for p in pk:
        if IPv6 in p:
            continue
        if ARP in p:
            a = p[ARP]
            if a.psrc in ROLES and a.pdst in ROLES and a.hwsrc.lower() in ROLE_MACS and a.hwdst.lower() in ROLE_MACS:
                keep.append(p)
            continue
        if IP in p and p[IP].src in ROLES and p[IP].dst in ROLES:
            if p.haslayer('TCP'):
                if 502 not in (p['TCP'].sport, p['TCP'].dport):
                    continue
            elif not p.haslayer('ICMP'):
                continue
            if Ether in p and (p[Ether].src.lower() not in ROLE_MACS or p[Ether].dst.lower() not in ROLE_MACS):
                continue
            keep.append(p)
    out = os.path.join(dst, os.path.basename(f))
    w = PcapNgWriter(out)
    for p in keep:
        w.write(p)
    w.close()
    stats[os.path.basename(f)] = {'original': len(pk), 'kept': len(keep)}
print(json.dumps(stats, indent=1))
