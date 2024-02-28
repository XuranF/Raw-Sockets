We provide two versions, one is normal version, the other one is for Extra Credit implementing Ethernet Frame and ARP protocol in layer 2:
- only TCP/IP: use `rawhttpget` 
- ARP, Ethernet Frame + IP + TCP: use `rawhttpget_arp_Bonus`

You can choose one to run:
1. To run rawhttpget:
    - sudo ethtool -K \<interface name> gro off
    - chmod +x rawhttpget
    - sudo ./rawhttpget \<url>

2. To run rawhttpget_arp_Bonus:
    - sudo ethtool -K \<interface name> gro off
    - replace all arguments 'ens33' with \<interface name> in code file (rawhttpget_arp_Bonus.py). 'ens33' location: line 23; line 96; line 114; line 132
    - chmod a+x rawhttpget_arp_Bonus
    - sudo ./rawhttpget_arp_Bonus \<url>
    - the program does not stop until it print "------------Onefin-------------", then the whole file downloaded.

High-level approach:
1. Use raw sockets to bypass the default operating system to enable customized TCP/IP/Ethernet headers.
2. Customize ARP Request, Ethernet Frame, TCP header, IP header and HTTP header based on RFC conventions to form a valid message to server.
3. Unpack response from server to separate ARP packket, Ethernet Frame, IP, TCP and HTTP headers, and save the final extracted HTML or other data forms such as bytes.
4. To enable a successful data transmission, first we need to establish a handshake with server; after establishing connection, we begin to send a GET request to server and wait for server's response(step 2); when server begins to send back response, we need to parse response from server while maintaing good nature of arriving packets such as no duplicate and/or out-of-order packets(step 3), after a valid packet is received, we need to send an acknowledgement message to server; after receiving all packets, terminate connection.

Implemented TCP/IP features:
1. Assemble correct TCP and IP headers, calculate checksum for each header field.
2. For each outgoing packets, use timestamp to set time out 60s
3. Filter arriving packets, identify IP addresses and port addresses.
4. Three-way handshake is established.
5. Ensure arriving packets are in order by comparing sequence number and acknowledgement number.
6. Send an acknowledgement back to server when a correct packet is confirmed
7. Appropriate congestion control techniques by adjusting congestion window.
8. Use OS APIs to find IP addresses of server and local.
9. Handle connection tear-down.

Implemented Ethernet Frame:
1. Assemble correct Ethernet Frame, choose correct protocol type field to support TCP/IP or ARP
2. Use API to get gateway ip and local host MAC address.
3. Broadcast Ethernet Frame with ARP request to query gateway MAC address.
4. Send Ethernet Frame with tcp/ip data to server.
5. Receive packet, unpack it, return tcp/ip packets to layer 3 function to parse ip and tcp headers.

Challenges:
1. Generate checksum for header fields, calculation uses one's complement algorithm which involves bit operations.
2. Generate headers for TCP and IP, need to pay close attention to each field, and understanding of RFC files is required. 
3. How to set appropriate APIs especially when a wrapper function may need to call a series of helper functions.
4. Transformation between bytes and strings in Python can be confusing, can easily cause bugs.
5. Choose suitable api to run commands to get local MAC address and gateway ip.
6. Handel the BlockingIOError when Ethernet socket recv() timeout and close.
7. Handel the data '000000' sent by server after GET request which will lead ack error.
8. Confirm FIN after receiving all packets, otherwise maybe unable to write the latest packet into file.
9. Parse ARP response and Ethernet Frame, gurantee protocol type to support both ARP and TCP/IP.
