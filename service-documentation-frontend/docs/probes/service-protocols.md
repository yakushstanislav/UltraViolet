# Service Protocols

UltraViolet ships ~100 protocol-specific probes, each speaking one
protocol and returning structured fields. This page is the full
inventory.

Columns:

- **Protocol** — the probe's identifier (also the `protocol` field on
  services in the API).
- **Default ports** — what the dispatcher routes to this probe.
- **Extracts** — the structured fields recorded.

## Web and TLS infrastructure

| Protocol | Default ports | Extracts |
|---|---|---|
| `http` | 80, 8000, 8008, 8080, 8081, 8443, 8888 (+TLS variants) | status, server, title, body, headers, redirects, robots, security.txt, favicon, technologies |
| `tls` | every port that completes a handshake | leaf cert, chain, SANs, JARM, JA3S, JA4S |
| technology detection | (runs on HTTP responses) | detected stack: Nginx, Apache, WordPress, Cloudflare, … |
| favicon | side-fetch on HTTP probes | mmh3 favicon hash |

## SSH / Remote shells

| Protocol | Default ports | Extracts |
|---|---|---|
| `ssh` | 22, 2222 | server version, KEX, host key, algorithms |
| `telnet` | 23 | banner, telnet negotiation hints |
| `rdp` | 3389 | NLA capabilities, X.224 negotiation, optional TLS leaf |
| `vnc` | 5900–5910 | RFB protocol version, security types |
| `x11` | 6000–6010 | display banner, supported byte order |

## File transfer

| Protocol | Default ports | Extracts |
|---|---|---|
| `ftp` | 21 | banner, AUTH TLS support, system type |
| `smb` | 139, 445 | dialect, computer name, signing |
| `nfs` | 2049 | versions, exports list |
| `rsync` | 873 | server version, module list |
| `afp` | 548 | AFP version, capabilities |
| `lpd` | 515 | banner |

## Mail

| Protocol | Default ports | Extracts |
|---|---|---|
| `smtp` | 25, 465, 587, 2525 | banner, EHLO capabilities, STARTTLS |
| `pop3` / `imap` | 110, 143, 993, 995 | banner, CAPABILITY response |

## Databases

| Protocol | Default ports | Extracts |
|---|---|---|
| `mysql` | 3306 | server version, auth plugin, character set |
| `postgresql` | 5432 | server version, SSL hint |
| `mssql` | 1433 | version, instance name, options |
| `oracle` | 1521 | listener banner, services |
| `mongodb` | 27017–27019 | isMaster reply, server version, auth required |
| `redis` | 6379 | INFO output, redis_version, modules |
| `memcached` | 11211 | stats output, version |
| `elasticsearch` | 9200 | cluster name, version, license |
| `etcd` | 2379, 2380 | version, cluster ID |

## Queues / Streaming / Service mesh

| Protocol | Default ports | Extracts |
|---|---|---|
| `kafka` | 9092 | ApiVersions, broker hints |
| `amqp` | 5672 | server properties, version |
| `nats` | 4222, 8222 | INFO frame, version, clusters |
| `mqtt` | 1883, 8883 | CONNACK, MQTT version |
| `zookeeper` | 2181 | stat / mntr four-letter responses |
| `envoy_admin` | 9901 | `/server_info` payload |
| `istio_pilot` | 15010, 15012, 15014 | gRPC reflection, version |
| `linkerd` | 4191 | proxy metrics endpoint |
| `cilium` | 9234, 9879 | Cilium agent identity |
| `nrpe` | 5666 | banner, capabilities |
| `alertmanager` | 9093 | `/api/v2/status` |
| `loki` | 3100 | `/loki/api/v1/status/buildinfo` |
| `tempo` | 3200 | service version |
| `victoriametrics` | 8428 | `/api/v1/status/buildinfo` |
| `datadog_agent` | 5000, 5001, 5005, 5012 | agent status JSON |
| `splunk` | 8000, 8089 | management API banner |
| `gocd` | 8153, 8154 | server version |
| `teamcity` | 8111 | banner, version |
| `proxmox` | 8006 | API banner, version |
| `docker` | 2375, 2376 | Engine version, OS |

## Identity / Directory / Auth

| Protocol | Default ports | Extracts |
|---|---|---|
| `ldap` | 389, 636, 3268, 3269 | rootDSE, naming contexts, SASL mechanisms |
| `ipmi` | 623/UDP | IPMI version, authentication capabilities |
| `ike` | 500/UDP, 4500/UDP | IKE version, supported transforms |

## DNS / Discovery / Time

| Protocol | Default ports | Extracts |
|---|---|---|
| `dns` | 53/TCP, 53/UDP | CHAOS TXT (`version.bind`), recursion flag |
| `dns_udp` | 53/UDP fast path | RCODE, RA flag |
| `dot` | 853 | DNS-over-TLS hint |
| `mdns` | 5353/UDP | service catalog, instance names |
| `snmp` | 161/UDP | sysDescr, sysName, sysObjectID |
| `ntp` | 123/UDP | version, mode, refid |

## VoIP / Messaging

| Protocol | Default ports | Extracts |
|---|---|---|
| `sip` | 5060, 5061 | Server header, allowed methods, classified vendor |
| `irc` | 6667, 6697 | server banner, network |
| `xiaomi_miio` | 54321/UDP | device announcement |
| `tuya` | 6668 | device ID hint |

## Industrial / SCADA / ICS

| Protocol | Default ports | Extracts |
|---|---|---|
| `modbus` | 502 | device ID, vendor, model |
| `bacnet` | 47808/UDP | device-id, vendor name |
| `dnp3` | 20000 | application layer banner |
| `iec104` | 2404 | startDT response |
| `dlms` | 4059 | DLMS/COSEM negotiation |
| `knx` | 3671/UDP | KNXnet/IP search response |
| `s7comm` | 102 | S7 product, module info |
| `enip` | 44818 | EtherNet/IP identity, vendor, product code |
| `niagara` | 4911 | Niagara/Fox banner |
| `codesys` | 1217, 2455 | CODESYS gateway info |
| `melsec` | 5006, 5007 | MELSEC frame response |
| `vxworks_wdb` | 17185/UDP | VxWorks debug agent |
| `c37118` | 4712 | IEEE C37.118 (PMU) header |
| `opcua` | 4840 | endpoint descriptions, server URI |
| `ocpp` | 8080, 8443 (WebSocket) | OCPP version negotiation |
| `iscsi` | 3260 | target IQN, portal list |

## Medical / Robotics / Energy / Mobility

| Protocol | Default ports | Extracts |
|---|---|---|
| `dicom` | 104, 2761, 11112 | C-ECHO response, called/calling AE |
| `hl7_mllp` | 2575 | MLLP banner, hospital system hint |
| `ros_master` | 11311 | XML-RPC `getSystemState` |
| `universal_robots` | 30001–30004 | RTDE banner, firmware |
| `tesla_wallconnector` | 80, 443 | firmware, serial |
| `adsb_dump1090` | 30001–30005 | dump1090 protocol banner |
| `ais_receiver` | 4001, 5000, 10110 | AIS NMEA stream sample |
| `nmea0183` | 10110, 2000 | NMEA sentence sample |

## Crypto / Blockchain

| Protocol | Default ports | Extracts |
|---|---|---|
| `bitcoin` | 8332, 8333 | `getnetworkinfo` reply, version |
| `ethereum_rpc` | 8545, 8546 | `web3_clientVersion`, `net_version` |

## IoT / Smart Home / Media

| Protocol | Default ports | Extracts |
|---|---|---|
| `rtsp` | 554, 8554 | DESCRIBE response, supported profiles |
| `onvif` | 80, 8080, 8000 (XML SOAP) | GetSystemInfo, GetProfiles, device manufacturer |
| `airplay` | 7000 | AirPlay version, model |
| `chromecast` | 8008, 8009 | device name, app id |
| `sonos` | 1400 | device info |
| `samsung_tv` | 8001, 8002 | device name, model |
| `webos_tv` | 3000, 3001 | webOS hint |
| `roku` | 8060 | ECP `/query/device-info` |
| `wemo` | 49152, 49153 | UPnP `/setup.xml` |
| `minecraft` | 25565 | server list ping (version, MOTD, players) |
| `edgex` | 59881 | EdgeX core-data version |
| `coap` | 5683/UDP | CoAP `/.well-known/core` |
| `jetdirect` | 9100 | PJL banner, model |
| `ipp` | 631 | printer attributes (`Get-Printer-Attributes`) |

## Backup / Storage

| Protocol | Default ports | Extracts |
|---|---|---|
| `bareos` | 9101, 9102, 9103 | Bareos daemon banner |
| `commvault` | 8400, 8401 | Commvault server banner |
| `veeam` | 9392, 9401 | Veeam REST API banner |

## Misc / Legacy

| Protocol | Default ports | Extracts |
|---|---|---|
| `ident` | 113 | ident banner |
| `rpc` | 111 | portmap dump |
| `pptp` | 1723 | Start-Control-Connection-Reply |
| `perforce` | 1666 | server banner, version |
| UDP runner | (meta) | UDP probe orchestration for `SCANNER_UDP_PROBE_PORTS` |

## Probe behaviour notes

### Banner probe timeout

Unknown ports fall through to the generic banner probe, which uses a
shorter `PROBE_BANNER_TIMEOUT` (default `2s`) instead of the full
`PROBE_TIMEOUT`. This prevents filtered or unresponsive ports from
occupying probe workers for the full probe budget.

### HTTP auxiliary requests

For every HTTP/HTTPS host the probe issues four auxiliary requests in
parallel: `/favicon.ico`, `/robots.txt`, `/.well-known/security.txt`,
and a random 404-probe path for body fingerprinting. Wall time is
therefore bounded by the slowest of the four, not their sum.

### DNS CHAOS fingerprinting

The DNS probe sends all CHAOS TXT queries (`version.bind`,
`hostname.bind`, `id.server`, `authors.bind`) in a single pipelined
burst over one TCP connection and matches responses by transaction ID.
Effective latency is one round-trip instead of one round-trip per
query.

### CVE matching

CVE matching for changed fingerprints is deferred until all probe
workers finish and is then dispatched in a bounded parallel batch (up
to 8 concurrent calls). Individual failures are ignored — the
background `cvematch` worker provides a safety net on its next run.

## Reminder

When a new probe is added, a row must be appended to this table in the
same commit. The `Documentation (Mandatory)` rule in `CLAUDE.md`
enforces this — changes missing a doc update are considered incomplete.
