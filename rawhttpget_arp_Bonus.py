#!/usr/bin/env python3
import socket
import struct
import sys
import time
import random
import binascii
import subprocess
import logging

#logging.basicConfig(filename='eth.log', level=logging.DEBUG)

#get gateway ip when destionation ip is not in the same LAN
def getGatewayIP():
    data = subprocess.getoutput('route -n').split('\n')
    #print(data) #debug
    for i in data:
        address = i.split()
        if address[0] == '0.0.0.0':
            print("gateway ip:", address[1])
            return address[1]

#get localhost mac address
def getMacAddr(interface = 'ens33'):
    data = subprocess.getoutput("ifconfig " + interface).split('\n')
    #print(data) #debug
    for i in data:
        address = i.split()
        if address[0] == "ether":
            print("mac address: ", address[1])
            return address[1].replace(':', '')

#get localhost ip
def getLocalhostIp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    localIP = s.getsockname()[0]
    print("local ip: ", localIP)
    s.close()
    return localIP

#arp packet used to find gateway MAC address
class arpPacket:
    def __init__(self):
        self.hType = 0x0001
        self.pType = 0x0800
        self.hSize = 6
        self.pSize = 4
        self.opcode = 1
        self.sourceMacAddr = ''
        self.sourceIP = ''
        self.destMac = ''
        self.destIp = ''

    #transfer ARP request packet into ARP response packet
    #raw_packet: response packet from socket.recv()
    def rebuild(self, raw_packet):
        [self.hType,
         self.pTypet,
         self.hSize,
         self.pSizes,
         self.opcode,
         src_mac,
         src_ip,
         dst_mac,
         dst_ip] = struct.unpack('!HHBBH6s4s6s4s', raw_packet)
        self.sourceMacAddr = binascii.hexlify(src_mac)
        self.sourceIP = socket.inet_ntoa(src_ip)
        self.destMac = binascii.hexlify(dst_mac)
        self.destIp = socket.inet_ntoa(dst_ip)

#Ethernet Frame used for TCP and ARP
class EthernetPacket:
    #default protocol = 0x0800: TCP
    #if protocol = 0x0806: ARP
    def __init__(self, source = '0', dest = '0', protocol = 0x0800, data = ''):
        self.source = source
        self.dest = dest
        self.type = protocol
        self.data = data

    #transfer ethernet request packet into response packet
    #raw_packet: from socket.recv()
    def rebuild(self, raw_packet):
        [dst, src, self.type] = struct.unpack('!6s6sH', raw_packet[:14])
        self.data = raw_packet[14:]
        self.source = binascii.hexlify(src)
        self.dest = binascii.hexlify(dst)

#use socket.AF_PACKET and socket.SOCK_RAW to create a socket to send and receive data
class EthernetSocket:
    def __init__(self):
        self.sourceMac = ''
        self.destMac = ''
        self.gatewayMac = ''
        self.sendSock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.sendSock.bind(('ens33', 0))
        self.recvSock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        self.recvSock.setblocking(0)

    #send data to server
    #data = ip header + tcp header + data(eg. http request)
    def send(self, data):
        #logging.debug('data: ' + str(data))
        if self.gatewayMac == '':
            #find gateway ip
            gatewayIp = getGatewayIP()
            try:
                #search destination mac address
                #create two arp socket
                arpsendsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                arprecvsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
                arprecvsock.settimeout(1)
                #get source MAC address
                self.sourceMac = getMacAddr('ens33')
                #get localhost ip
                sourceIP = getLocalhostIp()
                #create arp request packet
                arpRequest = arpPacket()
                arpRequest.sourceMacAddr = self.sourceMac
                arpRequest.sourceIP = sourceIP
                arpRequest.destIp = gatewayIp
                arpRequest.destMac = '000000000000'
                #pack ARP packet
                arp = struct.pack('!HHBBH6s4s6s4s', arpRequest.hType, arpRequest.pType, arpRequest.hSize, arpRequest.pSize, arpRequest.opcode, binascii.unhexlify(arpRequest.sourceMacAddr),socket.inet_aton(arpRequest.sourceIP), binascii.unhexlify(arpRequest.destMac), socket.inet_aton(arpRequest.destIp))
                #create ethernet packet
                #broadcast 'ffffffffffff', data = ARP packet, 0x0806 represent ARP
                packet = EthernetPacket(self.sourceMac, 'ffffffffffff', 0x0806, arp)
                #pack Ethernet frame = destination MAC address + source MAC address + protocol type + data(ip or arp)
                frame = struct.pack('!6s6sH', binascii.unhexlify(packet.dest), binascii.unhexlify(packet.source), packet.type) + packet.data
                #print("debug etframe: ", frame)
                #begin broadcast
                arpsendsock.sendto(frame, ('ens33', 0))
                while True:
                    #loop receive response
                    recv = arprecvsock.recv(4096)
                    #unpack recv packet
                    [dest, source, packet.type] = struct.unpack('!6s6sH', recv[:14])
                    packet.data = recv[14:]
                    packet.source = binascii.hexlify(source)
                    packet.dest = binascii.hexlify(dest)
                    packet.dest = packet.dest.decode("utf-8")
                    #determine if receiver is localhost
                    if packet.dest == self.sourceMac:
                        #transfer arp request packet into response packet
                        arpRequest.rebuild(packet.data[:28])
                        #determine if response is from gateway and if receiver ip is localhosts ip
                        if arpRequest.sourceIP == gatewayIp and arpRequest.destIp == sourceIP:
                            break
                arpsendsock.close()
                arprecvsock.close()
                self.gatewayMac = arpRequest.sourceMacAddr
            except:
                sys.exit('failed ARP Request ' + gatewayIp)
        self.destMac = self.gatewayMac
        #create ethernet packet
        packet = EthernetPacket(self.sourceMac, self.destMac, data = data)
        #assemble Ethernet Frame = destination MAC address + source MAC address + protocol type + data(ipdata) to send tcp/ip
        ethFrame = struct.pack('!6s6sH', binascii.unhexlify(packet.dest), binascii.unhexlify(packet.source), packet.type) + packet.data
        #send tcp/ip request
        self.sendSock.send(ethFrame)
        #debug
        #print("send: ", ethFrame)

    #receive data from server
    #t: advertised window size
    #return raw response from server
    def recv(self, t = 4096):
        packet = EthernetPacket()
        while True:
            try:
                rec = self.recvSock.recv(t)
                packet.rebuild(rec)
                #filter MAC address
                # if packet.dest.decode("utf-8") == self.sourceMac:
                #     print("rec:", rec)
                #     print("-------------------------------------------------------------------")
                #     return packet.data
                return packet.data
            except BlockingIOError as e:
                pass

    #close connection
    def close(self):
        self.sendSock.close()
        self.recvSock.close()

class MySocket(object):
    def __init__(self, remoteIP, portNumber):
        #self.sendSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        #self.recSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        #create ethernet socket
        self.sock = EthernetSocket()
        self.MSS = 1400
        self.cwnd = 1
        self.adv_wnd = 20480
        self.ack_num = 0
        self.seq_num = random.randint(20480, 40960)
        self.localIP = get_localIP()
        self.serverIP = remoteIP
        self.localPort = random.randint(0, 65535)
        self.serverPort = portNumber
        self.filename = 'index.html'
        # timers are used to save timestamp for each sent message
        self.timers = dict()

    # a wrapper function to send appropriate response to server
    def send(self, filename='', isACK=False, isPSH=False, isSYN=False, isFIN=False, payload=''):
        if filename != '':
            self.filename = filename
        message = self.IPHeader(payload) + self.TCPHeader(payload, isACK, isPSH, isSYN, isFIN) + payload.encode()
        self.sock.send(message)
        #self.sendSocket.sendto(message, (self.serverIP, self.serverPort))
        if len(payload) > 255:
            self.timers[message] = time.time()
            self.congestionControl()

    # congestion control by adjusting congestion window
    # specifically, iterate each timestamp to remove time-outed packet
    def congestionControl(self):
        hasCongestion = False
        for key in self.timers:
            if time.time() - self.timers[key] > 60:
                hasCongestion = True
                self.cwnd = 1
        if not hasCongestion:
            self.cwnd = min(1000, 2 * self.cwnd)

    # a wrapper function to deal with receiving, after confirming no duplicate and out-of-order packets
    # send an ACK back to server
    def receive(self):
        length = 0
        while True:
            segment = self.receivePacket()
            if len(segment) == 9:
                length = length + len(segment[8])
                #.log need "ISO-8859-1"
                if segment[8].decode("ISO-8859-1") == '\x00\x00\x00\x00\x00\x00':
                    if segment[4] == 1:  # if server send a FIN flag
                        print("--------------------------Onefin------------")
                        self.terminate(closedByServer=True)
                        #print("debug: length: ", length)
                        break
                    continue
                if segment[2] == self.ack_num:
                    # write into local file
                    if self.filename.endswith('.log'):
                        f = open("%s" % self.filename, "ab")
                        f.write(segment[8])
                    else:
                        f = open("%s" % self.filename, "a")
                        if segment[8].decode().startswith('HTTP/1.1 200 OK') == 1:
                            f.write(segment[8].decode().split('\r\n\r\n')[-1])
                            #print("debug:-------------------------writeHttp")
                        else:
                            f.write(segment[8].decode())
                            #print("debug:-------------------------write")
                    f.close()
                    # send back an ACK to server
                    self.seq_num = segment[3]
                    self.ack_num += len(segment[8])
                    #print("debug:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                    self.send(isACK=True)
                    continue
                if segment[4] == 1:  # if server send a FIN flag
                    #print("debug:--------------------------fin------------")
                    self.terminate(closedByServer=True)
                    break
            if len(segment) == 0:
                continue

            # make sure inorder as a receiver


    # three-way handshake to establish connection
    def connect(self):
        # send SYK
        self.send(isSYN=True)
        # receive SYK and ACK from server
        if self.receiveACK_connect():
            # update seq_num and ack_num, then send ACK again
            self.send(isACK=True)
        else:
            print('connection failed!')
            self.terminate()
            sys.exit(1)

    # helper function for establishing connection
    def receiveACK_connect(self):
        currentTime = time.time()
        while True:
            segment = self.receivePacket()
            if len(segment) == 0 and time.time() - currentTime < 60:
                continue
            if len(segment) == 0 and time.time() - currentTime >= 60:
                break
            if len(segment) > 0 and segment[5] == 1 and segment[6] == 1 and segment[3] - self.seq_num == 1:
                self.ack_num = segment[2] + 1
                self.seq_num = segment[3]
                return True
        return False

    # to terminate connection
    def terminate(self, closedByServer=False):
        #self.recSocket.close()
        #self.sendSocket.close()
        self.sock.close()

    # helper function to send valid-only packets back to caller functions
    def receivePacket(self):
        #rawPacket = self.recSocket.recv(self.adv_wnd)
        rawPacket = self.sock.recv(self.adv_wnd)
        # denotes the end of packet receiving
        if len(rawPacket) == 0:
            print('end of receiving')
            sys.exit(1)
        # unpack IP packet to extract TCP header and TCP payload
        packet = unpackIP(rawPacket)
        if len(packet) == 0:  # checksum is wrong or not TCP, ignore, waiting for server's timeout to resend
            #print('debug:checksum of IP header is wrong or not TCP protocol')
            return []
        # check sourceIP, desIP
        p0 = socket.inet_ntoa(packet[0])
        p1 = socket.inet_ntoa(packet[1])
        if self.serverIP != socket.inet_ntoa(packet[0]) or self.localIP != socket.inet_ntoa(packet[1]):
            #print('debug:invalid IP!')
            return []
        # unpack TCP packet to extract HTTP
        segment = unpackTCP(packet[-1])
        if len(segment) == 0:  # checksum is wrong, ignore, waiting for server's timeout to resend
            print('debug:checksum of TCP header is wrong')
            return []
        if self.serverPort != segment[0] or self.localPort != segment[1]:  # check port addresses
            #print("debug:error port")
            return []
        #print("debug: receive: ", segment)
        return segment

    # helper function to set up a valid IP header
    def IPHeader(self, payload):
        version = 4
        IHL = 5
        typeOfService = 0
        totalLength = 40 + len(payload.encode())
        identification = random.randint(0, 65535)
        segmentation_part = 1 << 14
        timeTL = 64
        protocol = 6
        checksum = 0  # a pseud checksum
        sourceIP = socket.inet_aton(self.localIP)
        desIP = socket.inet_aton(self.serverIP)
        # to obtain the real checksum
        checksum = checkSum(
            struct.pack('!BBHHHBBH4s4s', (version << 4) + IHL, typeOfService, totalLength, identification,
                        segmentation_part, timeTL, protocol, checksum, sourceIP, desIP),
            ifUnpacked=False)
        # after getting true checksum, pack the real IP header and ready to be sent
        return struct.pack('!BBHHHBB', (version << 4) + IHL, typeOfService, totalLength, identification,
                           segmentation_part, timeTL, protocol) + struct.pack('H', checksum) + struct.pack('4s4s',
                                                                                                           sourceIP,
                                                                                                           desIP)

    # helper function to set up a valid TCP header
    def TCPHeader(self, payload, isACK=False, isPSH=False, isSYN=False, isFIN=False):
        sourcePort = self.localPort
        destinationPort = self.serverPort
        sequenceNumber = self.seq_num
        ackNumber = self.ack_num
        hlen = 5
        ACK = 0
        SYN = 0
        FIN = 0
        PSH = 0
        if isACK:
            ACK = 1
        if isSYN:
            SYN = 1
        if isFIN:
            FIN = 1
        if isPSH:
            PSH = 1
        window = self.adv_wnd
        # use pseud checksum to calculate the real checksum
        checksum = checkSum(
            struct.pack('!4s4sBBHHHIIBBHHH', socket.inet_aton(self.localIP), socket.inet_aton(self.serverIP), 0, 6,
                        20 + len(payload.encode()), sourcePort, destinationPort, sequenceNumber, ackNumber, hlen << 4,
                        (ACK << 4) + (PSH << 3) + (SYN << 1) + FIN, window, 0, 0) + payload.encode(), ifUnpacked=False)
        # pack the real TCP header
        return struct.pack('!HHIIBBH', sourcePort, destinationPort, sequenceNumber, ackNumber, hlen << 4,
                           (ACK << 4) + (PSH << 3) + (SYN << 1) + FIN, window) + struct.pack('H',
                                                                                             checksum) + struct.pack(
            '!H', 0)


'''
Below are helper functions to unpack and check packets.
'''


def unpackIP(rawPacket):
    # list is of size 3, the first element is sourceIP, the second is desIP, last is payload
    # ref: https://stackoverflow.com/questions/20768107/regarding-struct-unpack-in-python
    tempList = []
    response = struct.unpack('!BBHHHBBH4s4s', rawPacket[:20])
    headerLength = extractBit(response[0], 1, 4)
    # check checksum, if checksum is wrong or not TCP protocol, return an empty list
    # if response[-3] != checkSum(rawPacket[:headerLength * 4]) or response[-4] != 6:
    # return tempList
    if response[-4] != 6:
        return tempList
    tempList.insert(0, response[-2])  # source IP
    tempList.insert(1, response[-1])  # des IP
    tempList.insert(2, rawPacket[headerLength * 4:])  # payload(TCP)
    return tempList


def unpackTCP(rawSegment):
    tempList = []
    response = struct.unpack('!HHIIBBHHH', rawSegment[:20])
    headerLength = extractBit(response[4], 5, 4)
    # if response[-2] != checkSum(rawSegment[:headerLength * 4]):
    # return tempList
    tempList.insert(0, response[0])  # source port address
    tempList.insert(1, response[1])  # destination port address
    tempList.insert(2, response[2])  # sequence number
    tempList.insert(3, response[3])  # acknowledgement number
    tempList.insert(4, extractBit(response[5], 1, 1))  # is FIN flag
    tempList.insert(5, extractBit(response[5], 2, 1))  # is SYN flag
    tempList.insert(6, extractBit(response[5], 5, 1))  # is ACK flag
    tempList.insert(7, response[-3])  # advertised window size
    if len(rawSegment) > headerLength * 4:
        tempList.insert(8, rawSegment[headerLength * 4:])  # payload(HTTP)
    return tempList


# calculate checksum for headers based on one's complementing
# https://stackoverflow.com/questions/1767910/checksum-calculation-for-icmpv6-in-python
def checkSum(header, ifUnpacked=True):
    tempList = bytearray(header)
    # in case length is odd, add paddings
    if len(tempList) % 2 == 1:
        tempList += struct.pack('B', 0)
    # zero out the checksum
    if ifUnpacked:
        tempList[10] = 0
        tempList[11] = 0
    # begin calculating
    checksum = 0
    for i in range(0, len(tempList), 2):
        w = tempList[i] + ((tempList[i + 1]) << 8)
        t = checksum + w
        checksum = (t & 0xffff) + (t >> 16)
    return ~checksum & 0xffff


# helper function to extract bit values, starting from 'begin' with an 'interval'
def extractBit(number, begin, interval):
    return ((1 << interval) - 1) & (number >> (begin - 1))


# get local IP address
# https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib?page=1&tab=scoredesc#tab-top
def get_localIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    localIP = s.getsockname()[0]
    s.close()
    return localIP


# get server IP address
def getRemoteIP(url):
    host = url.split("//")[-1].split("/")[0]
    return socket.gethostbyname(host)


# parse given url to extract host and path information
def parseUrl(url):
    host = url.split("//")[-1].split("/")[0]
    path = url.split("//")[-1].split("/", 1)[-1]
    filename = ''
    if path == host or not path:
        filename = 'index.html'
    else:
        path = '/' + path
        filename = url.split("//")[-1].split("/")[-1]
    return host, path, filename


# assemble the HTTP request
def httpRequest(host, path):
    msg = [
        'GET %s HTTP/1.1' % path,
        'Host: %s' % host]
    return '\r\n'.join(msg) + '\r\n\r\n'


# main function: initiate a customized socket first, then do a three-way handshake to establish connection
# after connecting with server, begin sending HTTP request with IP header and TCP header added
# wait for receiving and parse response from server
# terminate the connection once receiving all packets
def main(argv):
    print(getRemoteIP(argv[1]))
    s = MySocket(remoteIP=getRemoteIP(argv[1]), portNumber=80)
    s.connect()
    host, path, filename = parseUrl(argv[1])
    if not path:
        path = '/'
    s.send(filename, isACK=True, isPSH=True, payload=httpRequest(host, path))  # send HTTP GET request
    print("downloading......")
    s.receive()
    s.terminate()


if __name__ == '__main__':
    main(sys.argv)