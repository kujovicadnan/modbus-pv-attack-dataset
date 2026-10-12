# Modbus/TCP PV Inverter Attack Dataset

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23321340.svg)](https://doi.org/10.5281/zenodo.23321340)

Anonymised Wireshark packet captures from the experimental sessions described in:

**"Exploiting Modbus/TCP in Smart PV Systems: Sustained Command Injection and Denial-of-Service on Commercial Inverter Hardware"**

## Anonymisation and sanitisation

All MAC addresses of the four test roles have been replaced with anonymised values.
IP addresses are preserved as documented in the paper (192.168.178.0/24).

| Role | IP | Anonymised MAC |
|---|---|---|
| PV Inverter (Modbus server) | 192.168.178.181 | aa:bb:cc:11:22:33 |
| EV Wallbox (Modbus client) | 192.168.178.189 | aa:bb:cc:44:55:66 |
| Attacker (Raspberry Pi 4) | 192.168.178.159 | aa:bb:cc:77:88:99 |
| Router (AVM Fritz!Box) | 192.168.178.1 | aa:bb:cc:aa:bb:cc |

Vendor and model identifiers are withheld pending vendor remediation.

Since version 1.0.0 the captures contain only traffic between these four roles:
Modbus/TCP (port 502), ARP and ICMP. Unrelated traffic of other devices on the test
network (multicast DNS, DHCP, DNS, IPv6 and internet traffic) has been removed, because it
was not needed for the analysis and could identify third parties. The filter is
`github_dataset/sanitize_captures.py`. All Modbus function-code, request, response and
exception counts are identical to the original captures. Packet totals and the time span
between the first and the last retained packet are smaller, as listed below.

## Session Files

| File | Description | Duration (original) | Packets original / retained | Key Metric |
|---|---|---|---|---|
| `session1_injection_978s.pcapng` | FC3→FC6 injection, intermediate framework | 978 s | 3,050 / 1,372 | 18 FC6 exc. 0x02 |
| `session2_injection_working.pcapng` | FC3→FC6 injection, full stateful framework | 108.6 s | 433 / 203 | 30/43 FC3 = 69.8% |
| `session3_dos_persistent_832s.pcapng` | DoS Vector 2: persistent ARP poisoning | 832.6 s | 7,012 / 320 | 832 s disruption |
| `session4_probing_exc04_t5.pcapng` | Register probing: writable registers | 187.3 s | 688 / 147 | 15 FC6 exc. 0x04 |
| `session5_probing_exc04_t6.pcapng` | Register probing: writable registers | 249.1 s | 413 / 239 | 10 FC6 exc. 0x04 |
| `session6_baseline_recon.pcapng` | Baseline FC3 reconnaissance, no attack | 251.0 s | 934 / 463 | 102 FC3 req/resp |

## Key Findings Reproducible from Captures

- **Exception 0x02** in sessions 1 and 2: inverter processed all forged FC6 commands at application layer with no source authentication
- **Exception 0x04** in sessions 4 and 5: writable control registers identified; write attempted without authentication check
- **DoS persistence**: session 3 shows 832 seconds of communication disruption post-shutdown with no autonomous recovery
- **Attack transparency**: wallbox exhibits no error states during injection (synthetic FC3 responses accepted)

## Tools

Captures readable with Wireshark, tshark, and tcpdump.

```bash
# View Modbus traffic only
tshark -r github_dataset/pcaps/session2_injection_working.pcapng -Y modbus

# Count FC6 exception responses
tshark -r github_dataset/pcaps/session2_injection_working.pcapng -Y "modbus.exception_code == 2" | wc -l

# View register probing exceptions
tshark -r github_dataset/pcaps/session4_probing_exc04_t5.pcapng -Y "modbus.exception_code == 4"
```

## Responsible Disclosure

The affected vendor was contacted on 12 November 2025 with an in-person meeting.
No response was received after multiple follow-up attempts.
Model identifiers are withheld pending vendor remediation.

## License and citation

The captures and documentation are licensed under the Creative Commons Attribution 4.0
International License (CC BY 4.0), see `LICENSE`. Please cite the dataset as given in
`CITATION.cff`: Kujovic, A. (2026). Modbus/TCP PV Inverter Attack Dataset. Zenodo.
https://doi.org/10.5281/zenodo.23321340 (all versions; v1.0.0: 10.5281/zenodo.23321341).
