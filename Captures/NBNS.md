# NBNS capture

NBNS is specifically designed to work alongside DNS as a fallback mechanism. When a Windows client attempts to resolve a hostname to an IP address, it follows a strict Name Resolution Order:

1. Local Cache & Hosts File: The client checks if it recently resolved the name or if it is hardcoded in the local system files.

2. DNS Server: The client queries its configured DNS server (your AD Domain Controller).

3. LLMNR (Link-Local Multicast Name Resolution): If DNS fails, Windows attempts this modern multicast fallback to find local peers.

4. NBNS (NetBIOS Name Service): If all else fails, Windows uses this legacy protocol to broadcast its request to the entire local subnet.

## Scenario: Triggering NBNS Broadcasts

- Open Wireshark on your Windows client and start capturing traffic on your active Ethernet adapter.
- Open Command Prompt as an Administrator.
- Purge existing name caches to ensure the machine does not rely on previously saved resolutions by running ```ipconfig /flushdns``` followed by ```nbtstat -R```.
- Attempt to access a fake local server using a short NetBIOS name by running the command ```net view \\unknown-server```
- Since the DNS server (your DC) cannot resolve this fake name, Windows will fall back to broadcasting NBNS (and LLMNR) queries to the local subnet.

## Findings

### Wiresharks Analysis Checkpoints
| Packet Field   | Location in Packet Details            | What it Indicates                                                                                                                                                                                  |
| :------------- | :------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Transaction ID | NetBIOS Name Service > Transaction ID | Unique hexadecimal value used to match a specific name query to its corresponding response.                                                                                                        |
| Opcode         | Flags > Opcode                        | Defines the purpose of the packet. A `0` indicates a standard Name Query, while a `5` indicates a Name Registration attempt.                                                                       |
| Broadcast Flag | Flags > Broadcast                     | If set to 1, the client is shouting to the entire AD_LAN subnet (`destination MAC ff:ff:ff:ff:ff:ff`) because it doesn't know who holds the IP for the requested name.                             |
| Queried Name   | Queries > Name                        | The exact 15-character NetBIOS name the machine is searching for, padded with spaces if the name is shorter than 15 characters.                                                                    |
| NetBIOS Suffix | Queries > Name (16th byte)            | The hexadecimal tag indicating the specific service requested. Look for `<00>` (Workstation Service, general host discovery) or `<20>` (Server Service, typically used for file sharing requests). |

### Indicators

![alt text](/Captures//Images/PCAP.png)

Key Network Events Captured

- <b>DNS Failure</b>: The client (`10.10.10.51`) queries the local DNS server (`10.10.10.100`) for the A record of unknown-server.cyber.lan. The DNS server responds with a "No such name" error.

- <b>LLMNR Multicast</b>: Following the DNS failure, the client falls back to Link-Local Multicast Name Resolution (LLMNR), sending multicast queries over both IPv6 (`ff02::1:3`) and IPv4 (`224.0.0.252`) asking the local network for unknown-server.

- <b>NBNS Broadcast</b>: When LLMNR fails to resolve the name, the client attempts NetBIOS Name Service (NBNS) queries, broadcasting directly to the local subnet address (`10.10.10.255`) for UNKNOWN-SERVER<20>.

#### DNS
![alt text](/Captures//Images/DNS.png)

- <b>The Query</b>: The client at IP 10.10.10.51 asked the DNS server at 10.10.10.100 for the IPv4 address (an "A" record) of the hostname unknown-server.cyber.lan.

- <b>The Response</b>: The server replied via UDP port 53. The DNS Transaction ID (0xd21b) matches the client's request, linking the response to the query.

- <b>Reply Code</b>: The critical field is the Reply code under the Flags section, which reads No such name (3). This confirms that the requested hostname does not exist in the DNS zone.

#### LLMNR
![alt text](/Captures//Images/LLMNR.png)

- <b>Multicast Destinations</b>: Instead of asking a specific server, the client (10.10.10.51 and its IPv6 equivalent) broadcasts its requests to standardized multicast addresses. The traffic is sent to 224.0.0.252 over IPv4 and ff02::1:3 over IPv6, effectively asking the entire local network, "Who is unknown-server?"

- <b>Query Types</b>: The client simultaneously queries for both the IPv4 address (shown as an A record request) and the IPv6 address (shown as an AAAA record request) of the target hostname. 

#### NBNS
![alt text](/Captures/Images/NBNS.png)

![alt text](/Captures/Images/NBNS_Query.png)

NetBIOS Name Service (NBNS) response indicating a definitive failure to resolve a requested hostname.

- <b>Message Type</b>: While part of a query process, this specific packet is the Response, sent from a server (`10.10.10.100`) back to the client (`10.10.10.51`) over UDP port 137.

- <b>Reply Code</b>: The most important field is the Reply code under the Flags section: `Requested name does not exist (3)`. This confirms the queried NetBIOS name is not registered with this server.

- <b>Delivery Method</b>: The flags show `Broadcast: Not a broadcast packet`. This means it is a unicast response to a direct query. The client likely had `10.10.10.100` configured as a WINS server and asked it directly, rather than shouting to the whole network.

- This negative response from a designated WINS server forces the client to move to the next step in its resolution fallback chain: `broadcasting` the NBNS query to the entire local subnet (e.g., 10.10.10.255).

![alt text](/Captures/Images/NBNS_Broadcast.png)

- <b>The Query</b>: The client at IP `10.10.10.51` is actively asking the network to resolve the IPv4 address for the hostname `UNKNOWN-SERVER`.

- <b>Service Suffix</b>: The `<20>` appended to the queried name indicates the client is specifically looking for the "Server service" on the target machine, which is typically associated with SMB or file and print sharing.

- <b>Delivery Method</b>: The packet flags explicitly show `Broadcast: Broadcast packet`. It is sent to the subnet broadcast IP (`10.10.10.255`) and the Ethernet broadcast MAC address (`ff:ff:ff:ff:ff:ff`). This ensures every device on the local subnet receives and processes the request.

