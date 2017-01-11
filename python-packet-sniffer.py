import sys
import socket
import os
import struct
import threading

from ctypes import *

# http://stackoverflow.com/questions/29306747/python-sniffing-from-black-hat-python-book
host   = ""

class Ether(Structure):

    _fields_ = [
            ("dmac",     c_ubyte*6),
            ("smac",     c_ubyte*6),
            ("ethertype",   c_ushort)
            ]

    def __new__(self, socket_buffer=None):
        # https://docs.python.org/2/library/ctypes.html#ctypes._CData.from_buffer_copy
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.dst_mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (self.dmac[0] , self.dmac[1], self.dmac[2], self.dmac[3], self.dmac[4], self.dmac[5])
        self.src_mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (self.smac[0] , self.smac[1], self.smac[2], self.smac[3], self.smac[4], self.smac[5])

        self.protocol_map = {
                8:"IPv4",
                1544:"ARP",
                56710:"IPv6"
                }
        try:
            self.protocol = self.protocol_map[self.ethertype]
        except:
            self.protocol = self.ethertype


class ARP(BigEndianStructure):
    # ctypes uses the native byte order for Structures and Unions.
    # To build structures with non-native byte order, you can use one of the BigEndianStructure, LittleEndianStructure  base classes.

    # http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
    _fields_ = [
            ("hrd",     c_ushort), # hardware type
            ("pro",     c_ushort), # protocol type
            ("hln",     c_ubyte),  # hardware address len
            ("pln",     c_ubyte),  # protocol address len
            ("op",      c_ushort)  # opcode
            ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):

        self.hrd_map = { # http://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
                1:"Ethernet",
                6:"IEEE 802 Networks",
                7:"ARCNET",
                15:"Frame Relay",
                16:"Asynchronous Transfer Mode (ATM)",
                17:"HDLC",
                18:"Fibre Channel",
                19:"Asynchronous Transfer Mode (ATM)",
                20:"Serial Line",
                21:"Asynchronous Transfer Mode (ATM)"
                }
        try:
            self.hrd_type = self.hrd_map[self.hrd]
        except:
            self.hrd_type = str(self.hrd)

        if self.pro == 2048: # For IPv4 addresses, this value is 2048 (0800 hex), which corresponds to the EtherType code for the Internet Protocol
            self.pro_type = "IPv4"
        else:
            self.pro_type = str(self.pro)

        self.op_map = {
                1:"ARP Request",
                2:"ARP Reply",
                3:"RARP Request",
                4:"RARP Reply",
                5:"DRARAP Request",
                6:"DRARP Reply",
                7:"DRARP Error",
                8:"InARP Request",
                9:"InARP Reply"
                }
        try:
            self.opcode = self.op_map[self.op]
        except:
            self.opcode = self.op

        if self.hln == 6:
            self.sha_b = struct.unpack("!6B", socket_buffer[8:14]) # sender hardware address
            self.sha = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (self.sha_b[0] , self.sha_b[1], self.sha_b[2], self.sha_b[3], self.sha_b[4], self.sha_b[5])
            self.tha_b = struct.unpack("!6B", socket_buffer[14 + self.pln : 20 + self.pln]) # target hardware address
            self.tha = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (self.tha_b[0] , self.tha_b[1], self.tha_b[2], self.tha_b[3], self.tha_b[4], self.tha_b[5])
        else:
            self.sha = "mac size != 6"
            self.tha = "mac size != 6"

        if self.pln == 4:
            self.spa_b = struct.unpack("!4B", socket_buffer[8 + self.hln : 12 + self.hln]) # sender protocol address / IP
            self.tpa_b = struct.unpack("!4B", socket_buffer[12 + self.hln*2 : 16 + self.hln*2]) # target protocol address / IP
        else:
            self.spa = "spa size != 4"
            self.tpa = "tpa size != 4"


class IP(Structure):

    # struct.calcsize('@BBHHHBBHLL')
    #is 20 in i386 and 32 in amd64 which is size of _fields_.
    _fields_ = [
        ("ihl",             c_ubyte, 4),
        ("version",         c_ubyte, 4),
        ("TOS_Precedence",  c_ubyte, 3), # https://tools.ietf.org/html/rfc1349
        ("TOS_Bits",        c_ubyte, 4),
        ("TOS_MBZ",         c_ubyte, 1),
        ("len",             c_ushort),
        ("id",              c_ushort),
        ("flags_and_offset",c_ushort),
        ("ttl",             c_ubyte),
        ("protocol_num",    c_ubyte),
        ("checksum",        c_ushort),
        ("src",             c_uint32), # c_ulong is 4 bytes in i386 and 8 in amd64
        ("dst",             c_uint32)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):

        self.TOS_Precedence_map = {
                0:"Best Effort",
                1:"Priority",
                2:"Immediate",
                3:"Flash (voice signaling)",
                4:"Flash Override",
                5:"Critical (voice RTP)",
                6:"Internetwork Control",
                7:"Network Control"
                }
        self.TOS_Precedence_meaning = self.TOS_Precedence_map[self.TOS_Precedence]

        self.TOS_Bits_map = { # https://tools.ietf.org/html/rfc1349
                1000:"Minimize Delay [ftp, telnet, ssh..]",
                100 :"Maximize Throughput [ftp-data, www, zone-transfer..]",
                10  :"Maximize Reliability [snmp, dns..]",
                1   :"Minimize Monetary Cost [nntp, smtp..]",
                0000:"Normal Service"
                }
        self.TOS_Bits_value = int(bin(self.TOS_Bits)[2:])
        try:
            self.TOS_Bits_meaning = self.TOS_Bits_map[self.TOS_Bits_value]
        except:
            self.TOS_Bits_meaning = "Unknown TOS field value %d" % self.TOS_Bits_value

        self.total_length = self.len/256

        self.flags = self.flags_and_offset >>13 # https://en.wikipedia.org/wiki/IPv4#Flags
        self.flags_map = {
                0:"Not set",
                1:"More fragments",
                2:"Don't fragment",
                4:"Evil bit" #https://tools.ietf.org/html/rfc3514
                }
        try:
            self.flags_meaning = self.flags_map[self.flags]
        except:
            self.flags_meaning = "Flags value %d not mapped" % self.flags

        self.frag_offset = self.flags_and_offset & 0x1fff

        self.protocol_map = { # map protocol constants to their names
                1:"ICMP",
                2:'IGMP',
                6:"TCP",
                17:"UDP",
                103:'PIM'
                }
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

        self.header_checksum = struct.unpack("<H", struct.pack(">H",self.checksum))[0]

        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))# human readable IP addresses

        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))


class ICMP(Structure):

    _fields_ = [
            ("type",        c_ubyte),
            ("code",        c_ubyte),
            ("checksum",    c_ushort),
            ("unused",      c_ushort),
            ("next_hop_mtu",c_ushort)
            ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        self.icmp_types = {
                0:"Echo Reply",
                3:"Dest Unreachable",
                4:"Source Quench",
                8:"Echo Request"}
        self.type_3_codes = {
                0:"Net Unreachhable",
                1:"Host Unreachable",
                2:"Protocol Unreachable",
                3:"Port Unreachable",
                4:"Source Quench",
                5:"Source Route Failed"}


class IGMP(Structure):
    # https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
    # https://tools.ietf.org/html/rfc2236
    # https://tools.ietf.org/html/rfc3376
    _fields_ = [
            ("type",            c_ubyte),
            ("maxRespTime",     c_ubyte),
            ("checksum",        c_ushort),
            ("groupAddress",    c_uint32)
            ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        self.igmp_types_map = {
                17:'Membership Query', # 0x11
                18:'Version 1 Membership Report', # 0x12
                22:'Version 2 Membership Report', # 0x16
                23:'Leave Group' # 0x17
                }
        try:
            self.igmp_type = self.igmp_types_map[self.type]
        except:
            self.igmp_type = str(self.type)

        self.header_checksum = struct.unpack("<H", struct.pack(">H",self.checksum))[0]

        self.grpAddr = socket.inet_ntoa(struct.pack("@I", self.groupAddress))


class TCP(Structure):

    #-------------------#
    # TO-DO:
    # ctypes uses the native byte order for Structures and Unions.
    # To build structures with non-native byte order, you can use one of the BigEndianStructure, LittleEndianStructure  base classes.
    # i.e. change "Structure" to "BigEndianStructure" to get rid of all those struct.unpack below...
    #-------------------#

    _fields_ = [ # https://tools.ietf.org/html/rfc793#page-15
            ("src_port",    c_ushort),
            ("dst_port",    c_ushort),
            ("seq_num",     c_uint32),
            ("ack_num",     c_uint32),
            ("ushort",      c_ushort),
            ("window",      c_ushort),
            ("checksum",    c_ushort),
            ("urg_pointer", c_ushort)
            ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        # bytes must be swapped to get actual values
        self.source_port = struct.unpack("<H", struct.pack(">H",self.src_port))[0]
        self.destination_port = struct.unpack("<H", struct.pack(">H",self.dst_port))[0]
        self.sequence_number = struct.unpack("<I", struct.pack(">I",self.seq_num))[0]
        self.acknowledgment_number = struct.unpack("<I", struct.pack(">I",self.ack_num))[0]

        self.offset_and_ctrl = struct.unpack("<H", struct.pack(">H",self.ushort))[0]

        self.data_offset = (self.offset_and_ctrl >> 12) * 4
        self.reserved = (self.offset_and_ctrl >> 9) & 0x0007
        self.NS = (self.offset_and_ctrl >> 8) & 0x0001
        self.CWR = (self.offset_and_ctrl >> 7) & 0x0001
        self.ECE = (self.offset_and_ctrl >> 6) & 0x0001
        self.URG = (self.offset_and_ctrl >> 5) & 0x0001
        self.ACK = (self.offset_and_ctrl >> 4) & 0x0001
        self.PSH = (self.offset_and_ctrl >> 3) & 0x0001
        self.RST = (self.offset_and_ctrl >> 2) & 0x0001
        self.SYN = (self.offset_and_ctrl >> 1) & 0x0001
        self.FIN = self.offset_and_ctrl & 0x0001


        self.tcp_window = struct.unpack("<H", struct.pack(">H",self.window))[0]
        self.tcp_checksum = struct.unpack("<H", struct.pack(">H",self.checksum))[0]
        self.urgent_pointer = struct.unpack("<H", struct.pack(">H",self.urg_pointer))[0]

        self.options_map = {
                2:[4,"Maximum Segment Size"],
                3:[3,"Windows Scale"],
                4:[2,"SACK Permitted"],
                8:[10,"Timestamps"],
                10:["3","Partial Order Service Profile"]
                }


    # http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
    # http://www.firewall.cx/networking-topics/protocols/tcp/138-tcp-options.html
    def unpack_options(self, options):
        print "\t\t\tOptions:"
        s =  struct.unpack("!%dB" % len(options), options) # options are one octed/byte chunks
        c = 0
        while c < len(s):
            if s[c] == 0:
                print "\t\t\t\tEOL"
                break
            elif s[c] == 1:
                print "\t\t\t\tNOP"
            else:
                try:
                    option_type = self.options_map[s[c]] # try to map the octet where the pointer is at to an option type
                    option_len = option_type[0] # the next octet indicates the option length
                    option_name = option_type[1]

                    if option_name == "Timestamps":
                        print "\t\t\t\t%s:" % option_name
                        value, echo_reply = struct.unpack_from("!2I", options, c+2)
                        print "\t\t\t\t\tValue: \t%d" % value
                        print "\t\t\t\t\tEcho Reply: %d" % echo_reply
                    else:
                        print "\t\t\t\t%s" % option_name
                        l = 2 # skip the first two octets which are for tpe and length
                        while l < option_len:
                            print "\t\t\t\t\t%d" %  s[c+l]
                            l += 1
                    c += (option_len -1 ) # -1 is to account for the c+=1 after the loop
                except:
                    try:
                        print "\t\t\t\t%d (unknown option), length %d bytes" % (s[c], s[c+1])
                        length = s[c+1]
                        l = 2
                        while l < length:
                            print "\t\t\t\t\t%d" % s[c+l]
                            l += 1
                        c += (length -1)
                    except:
                        print "mapping option %s failed, quitting..." % s[c]
                        break
            c += 1



class UDP(BigEndianStructure):

    _fields_ = [
            ('src_port',    c_ushort),
            ('dst_port',    c_ushort),
            ('length',      c_ushort),
            ('checksum',    c_ushort)
            ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

    def hexdump(self, src, length=16):
        result = []
        digits = 4 if isinstance(src, unicode) else 2

        for i in xrange(0, len(src), length):
           s = src[i:i+length]
           hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
           text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
           result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )

        print b'\n'.join(result)


class DNS(Structure):

    #-------------------#
    # TO-DO:
    # ctypes uses the native byte order for Structures and Unions.
    # To build structures with non-native byte order, you can use one of the BigEndianStructure, LittleEndianStructure  base classes.
    # i.e. change "Structure" to "BigEndianStructure" to get rid of all those struct.unpack below...
    #-------------------#

    # http://www.networksorcery.com/enp/protocol/dns.htm
    # http://www.tcpipguide.com/free/t_TCPIPDomainNameSystemDNS.htm
    # http://www.zytrax.com/books/dns/ch15/
    _fields_ = [
            ('id',          c_ushort),
            ('ushort',      c_ushort),
            ('tot_questions',       c_ushort),
            ('tot_answer_RRs',      c_ushort),
            ('tot_authority_RRs',   c_ushort),
            ('tot_additional_RRs',  c_ushort)
            ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):

        self.identification = struct.unpack("<H", struct.pack(">H",self.id))[0]

        self.flags = struct.unpack("<H", struct.pack(">H",self.ushort))[0]

        self.QR = (self.flags >> 15) & 0x0001
        if self.QR == 0:
            self.qr = "Query"
        else:
            self.qr = "Response"

        self.opcode = (self.flags >> 11) & 0x000f
        self.opcode_map = {
                0:'Standard Query',
                1:'Inverse Query',
                2:'Server Status Request',
                3:'op 3 Reserved?',
                4:'Notify',
                5:'Update'
                }
        try:
            self.Opcode = self.opcode_map[self.opcode]
        except:
            self.Opcode = "op %d Reserved" % self.opcode

        self.AA = (self.flags >> 10) & 0x0001
        self.TC = (self.flags >> 9) & 0x0001
        self.RD = (self.flags >> 8) & 0x0001
        self.RA = (self.flags >> 7) & 0x0001
        self.Z = (self.flags >> 6) & 0x0001
        self.AD = (self.flags >> 5) & 0x0001
        self.CD = (self.flags >> 4) & 0x0001

        self.rcode = self.flags & 0x000f
        self.rcode_map = {
                0:'No error.',
                1:'Format error. The name server was unable to interpret the query.',
                2:'Server failure. The name server was unable to process this query.',
                3:'Name Error. The domain name referenced in the query does not exist.',
                4:'Not Implemented. The name server does not support the requested kind of query.',
                5:'Refused. The name server refuses to perform the specified operation (e.g., zone transfer).',
                6:'YXDomain. Name Exists when it should not',
                7:'YXRRSet. RR Set Exists when it should not.',
                8:'NXRRSet. RR Set that should exist does not.',
                9:'NotAuth. Server Not Authoritative for zone.',
                10:'NotZone. Name not contained in zone.',
                16:'BADVERS.Bad OPT Version. BADSIG.TSIG Signature Failure.',
                17:'BADKEY. Key not recognized.',
                18:'BADTIME. Signature out of time window.',
                19:'BADMODE. Bad TKEY Mode.',
                20:'BADNAME. Duplicate key name.',
                21:'BADALG. Algorithm not supported.',
                22:'BADTRUNC. Bad truncation.'
                }
        try:
            self.Rcode = self.rcode_map[self.rcode]
        except:
            self.Rcode = "Rcode %d unknown" % self.rcode


        self.quest = struct.unpack("<H", struct.pack(">H",self.tot_questions))[0]
        self.answ_RRs = struct.unpack("<H", struct.pack(">H",self.tot_answer_RRs))[0]
        self.auth_RRs = struct.unpack("<H", struct.pack(">H",self.tot_authority_RRs))[0]
        self.add_RRs = struct.unpack("<H", struct.pack(">H",self.tot_additional_RRs))[0]


        self.qtypes_map = { # http://www.networksorcery.com/enp/rfc/rfc1035.txt
                1:"A",
                2:"NS",
                5:"CNAME",
                6:"SOA",
                11:"WKS",
                12:"PTR",
                15:"MX",
                28:"AAAA",
                33:"SRV",
                255:"A request for all records"
                }

        self.qclass_map = {
                0:"Reserved",
                1:"IN",
                3:"CH, Chaos",
                4:"HS, Hesoid",
                255:"Any (QCLASS only)"
                }


    def print_qa(self, queries, z, answ):

        def print_label(self, queries, z):

            #s =  struct.unpack("!%dB" % len(queries), queries) # options are one octed/byte chunks
            p = lambda x: struct.unpack("!B", queries[x])[0]
            try:
                label = ""

                # crazy loop, to account for pointers that point to another pointer
                # it is only 2 levels deep, hopefully I won't need more.
                # there is probably a better way to write it, but who's got time..
                if p(z) == 192:# 0xc0 or binary 11000000 indicates dns compression aka. pointer
                    z += 1
                    pointer = p(z) - 12
                    # subtract 12 bytes of DNS header, to place the pointer at "queries"
                    while p(pointer) != 0:
                        name_len = int(p(pointer))
                        pointer += 1 # pointer at the start of the name
                        name = queries[pointer : pointer + name_len]
                        label += name+"."
                        pointer += name_len
                        if p(pointer) == 192:
                            # z += 1
                            pointer += 1 # incrementing pointer rather than 'z'
                            pointer = p(pointer) - 12 # this yields the pointer0s relative position
                            while p(pointer) != 0:
                                name_len = int(p(pointer))
                                pointer += 1 # pointer at the start of the name
                                name = queries[pointer : pointer + name_len]
                                label += name+"."
                                pointer += name_len
                            break # just trust me, you need this

                elif p(z) == 0:
                    label = "<Root>"

                else:
                    while p(z) != 0:
                        name_len = int(p(z))
                        z += 1 # pointer at the start of the name
                        name = queries[z : z + name_len]
                        label += name+"."
                        z += name_len
                        if p(z) == 192:
                            z += 1
                            pointer = p(z) - 12
                            while p(pointer) != 0:
                                name_len = int(p(pointer))
                                pointer += 1 # pointer at the start of the name
                                name = queries[pointer : pointer + name_len]
                                label += name+"."
                                pointer += name_len
                            break


                z += 1

                self.z = z
                self.label = label
                return (self.label,self.z)

            except Exception as e:
                print e

        print_label(self, queries, z) # Function to try and print labels/names
        print "\t\t\t\t\tname:\t\t%s" % self.label

        # Print type and class
        try:
            qtypes = struct.unpack("!H", queries[self.z:self.z+2])
            qtype = self.qtypes_map[int(qtypes[0])]
            print "\t\t\t\t\ttype:\t\t%s" % qtype
        except:
            print "\t\t\t\t\ttype:\t\t%d" % qtypes
        self.z += 2
        try:
            qclasses = struct.unpack("!H", queries[self.z:self.z+2])
            qclass = self.qclass_map[int(qclasses[0])]
            print "\t\t\t\t\tclass:\t\t%s" % qclass
        except:
            print "\t\t\t\t\tclass:\t\t%d" % qclasses
        self.z += 2

        # If the response contains dns answers
        if answ == True:
            ttl = struct.unpack("!I", queries[self.z:self.z+4])[0]
            self.z += 4
            rdlength = struct.unpack("!H", queries[self.z:self.z+2])[0]
            self.z += 2
            #rdata = queries[z:z+rdlength]
            #z += rdlength

            print "\t\t\t\t\tttl:\t\t%d seconds" % ttl
            print "\t\t\t\t\trdlength:\t%d" % rdlength

            if qtype == "A":
                self.ns_ip = struct.unpack("!4B", queries[self.z:self.z+4])
                print "\t\t\t\t\tAddress:\t%d.%d.%d.%d" % (self.ns_ip[0], self.ns_ip[1], self.ns_ip[2], self.ns_ip[3])
                self.z += 4
            elif qtype == "SOA":
                # first print 2 variable length labels
                print_label(self, queries, self.z)
                print "\t\t\t\t\tPrimary NS:\t%s" % self.label
                print_label(self, queries, self.z)
                print "\t\t\t\t\tAdmin MB:\t%s" % self.label

                # five unsigned 32 bit integers
                serial_number = struct.unpack("!I", queries[self.z:self.z+4])[0]
                print "\t\t\t\t\tSerial number:\t%d" % serial_number
                self.z += 4
                refresh_interval = struct.unpack("!I", queries[self.z:self.z+4])[0]
                print "\t\t\t\t\tRefresh:\t%d (%d minutes)" % (refresh_interval, refresh_interval/60)
                self.z += 4
                retry_interval = struct.unpack("!I", queries[self.z:self.z+4])[0]
                print "\t\t\t\t\tRetry:\t\t%d (%d minutes)" % (retry_interval, retry_interval/60)
                self.z += 4
                expire_limit = struct.unpack("!I", queries[self.z:self.z+4])[0]
                print "\t\t\t\t\tExpire limit:\t%d (%d days)" % (expire_limit, expire_limit/86400)
                self.z += 4
                minimum_ttl = struct.unpack("!I", queries[self.z:self.z+4])[0]
                print "\t\t\t\t\tMinimum TTL:\t%d (%d days)" % (minimum_ttl, minimum_ttl/86400)
                self.z += 4
            elif qtype == "MX":
                preference = struct.unpack("!H", queries[self.z:self.z+2])[0]
                print "\t\t\t\t\tPreference:\t%d" % preference
                self.z += 2
                print_label(self, queries, self.z)
                print "\t\t\t\t\tMail exchanger:\t%s" % self.label
            elif qtype == "AAAA":
                print "\t\t\t\t\tIPv6 format not defined yet"
                self.z += 16
            elif qtype == "PTR" or qtype == "NS" or qtype == "CNAME":
                print_label(self, queries, self.z)
                print "\t\t\t\t\tHost/NS name:\t%s" % self.label
            else:
                print "\t\t\t\t\tRdata format unknown for type %s" % qtypes

        return self.z



class DHCP(Structure):

    # https://tools.ietf.org/html/rfc951
    # https://tools.ietf.org/html/rfc2131
    _fields_ = [
            ('op',      c_ubyte),
            ('htype',   c_ubyte),
            ('hlen',    c_ubyte),
            ('hops',    c_ubyte),
            ('xid',     c_uint),
            ('secs',    c_ushort),
            ('flags',   c_ushort),
            ('ciaddr',  c_uint), # client IP address; filled in byu client if known
            ('yiaddr',  c_uint), # 'your' (client) IP address; filled bu server if client doesn't know its own address
            ('siaddr',  c_uint), # server IP address; returned in bootreply by server
            ('giaddr',  c_uint), # gateway IP address; used in optional  cross gateway booting
            ('chaddr',  c_ubyte*16), # client hardware address filled in by client, + 10 bytes padidng
            ('sname',   c_char*64), # optional server host name, null terminated string
            ('bfile',   c_char*128) # boot file name, null terminated string; 'generic' name or null in bootrequest, fully qualified directory-path name in bootreply.
            ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):

        self.xidd = struct.unpack("<I", struct.pack(">I",self.xid))[0]
        self.ciaddrr = socket.inet_ntoa(struct.pack("@I",self.ciaddr))
        self.yiaddrr = socket.inet_ntoa(struct.pack("@I",self.yiaddr))
        self.siaddrr = socket.inet_ntoa(struct.pack("@I",self.siaddr))
        self.giaddrr = socket.inet_ntoa(struct.pack("@I",self.giaddr))
        self.chaddrr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (self.chaddr[0], self.chaddr[1], self.chaddr[2], self.chaddr[3], self.chaddr[4], self.chaddr[5])

        self.options_codes = {
                1:'Subnet Mask',
                2:'Time Offset',
                3:'Router',
                6:'DNS',
                12:'Host Name',
                15:'Domain Name',
                16:'Domain Name Server',
                26:'Interface MTU',
                28:'Broadcast Address',
                50:'Requested IP Address',
                51:'Address Lease Time',
                53:'DHCP',
                54:'Server Identifier',
                55:'Parameter Request List'
                }
                # https://tools.ietf.org/html/rfc1533
                # https://tools.ietf.org/html/rfc1497
        self.DHCP_message_type = {
                    1:'Discover',
                    2:'Offer',
                    3:'Request',
                    4:'Decline',
                    5:'ACK',
                    6:'NAK',
                    7:'Release'
                    }

    def print_options(self, socket_buffer=None):

        i = 4 # 236 is the DHCP header length, plus 4 bytes of magic cookie = 240
        print "\t\t\t\tOptions:"
        # magic_cookie = "%x %x %x %x" % (socket_buffer[236], socket_buffer[237], socket_buffer[238], socket_buffer[239])
        while i <= len(socket_buffer):
            self.option_code = ord(socket_buffer[i])
            if self.option_code == 255:
                print "\t\t\t\t\t[{:2d}]\t{:20s}".format(self.option_code, "End")
                break
            try:
                self.option_type = self.options_codes[self.option_code]
                i += 1
                self.option_len = ord(socket_buffer[i])
                i += 1
                self.option_data = socket_buffer[i : i + self.option_len]

                cute_print = "\t\t\t\t\t[{:2d}]\t{:25s}:\t".format(self.option_code, self.option_type)
                print cute_print,

                if (self.option_type == "Subnet Mask" or
                    self.option_type == "Broadcast Address" or
                    self.option_type == "Server Identifier" or
                    self.option_type == 'Router' or
                    self.option_type == 'Requested IP Address'):
                    self.byte = struct.unpack("!%dB" % self.option_len, self.option_data)
                    print "%d.%d.%d.%d" % (self.byte[0], self.byte[1], self.byte[2], self.byte[3])

                elif self.option_type == 'DHCP':
                    print self.DHCP_message_type[ord(self.option_data)]

                elif self.option_type == 'DNS':
                    self.byte = struct.unpack("!%dB" % self.option_len, self.option_data)
                    x = 4
                    q,w,e,r = 0,1,2,3
                    while x <= self.option_len:
                        if x != self.option_len:
                            print "%d.%d.%d.%d |" % (self.byte[q], self.byte[w], self.byte[e], self.byte[r]),
                        else:
                            # if this if the last ip, print with newline
                            print "%d.%d.%d.%d" % (self.byte[q], self.byte[w], self.byte[e], self.byte[r])
                        q,w,e,r = q+4,w+4,e+4,r+4
                        x += 4

                elif self.option_type == 'Address Lease Time':
                    self.time = struct.unpack('!I', self.option_data)
                    print "%d seconds" % self.time

                elif (self.option_type == 'Domain Name') or (self.option_type == 'Host Name'):
                    self.dn = struct.unpack("!%dc" % self.option_len, self.option_data)
                    self.string = ""
                    for c in self.dn:
                        self.string += c
                    print self.string

                else:
                    self.option_uchars = struct.unpack("!%dB" % self.option_len, self.option_data)
                    print self.option_uchars
                i += self.option_len

            except:
                self.option_type = "Unknown Option"
                i += 1
                self.option_len = ord(socket_buffer[i])
                i += 1
                self.option_data = socket_buffer[i : i + self.option_len]

                cute_print = "\t\t\t\t\t[{:2d}]\t{:25s}:\t".format(self.option_code, self.option_type)
                print cute_print,

                self.option_uchars = struct.unpack("!%dB" % self.option_len, self.option_data)
                print self.option_uchars
                i += self.option_len
                continue




# create a raw socket and bind it to the public interface
#if os.name == "nt":
#    socket_protocol = socket.IPPROTO_IP
#else:
#    socket_protocol = socket.IPPROTO_ICMP
#
#sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
#
#sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
#


# count = 1

try:
    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    #sniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    ETH_P_ALL = 0x0003
    sniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    # if we're on Windows we need to send some ioctls to setup promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
except socket.error, msg:
    print "Socket could not be created. Error Code: %s Message %s" % (str(msg[0]), msg[1])
    sys.exit()

try:
    while True:

        # read in a single packet
        raw_buffer = sniffer.recvfrom(65565)[0]

        eth_header = Ether(raw_buffer[:14]) # Ethernet header is 14 bytes

       # print
       # print count
       # count += 1
        print
        print "Ether >>"
        print "\tDst MAC:\t\t%s" % eth_header.dst_mac
        print "\tSrc MAC:\t\t%s" % eth_header.src_mac
        print "\tProtocol:\t\t%s" % eth_header.protocol

        if eth_header.protocol == "IPv4":

            ip_header = IP(raw_buffer[14:])

            print
            print "\tIP >>"
            print "\t\tHeader Length:\t\t%s bytes" % str(ip_header.ihl * 4)
            print "\t\tVersion:\t\t%s" % str(ip_header.version)
            print "\t\tTOS Precedence:\t\t%d\t%s" % (ip_header.TOS_Precedence, ip_header.TOS_Precedence_meaning)
            print "\t\tTOS bits:\t\t%04d\t%s" % (ip_header.TOS_Bits_value, ip_header.TOS_Bits_meaning)
            print "\t\tTotal Length:\t\t%d bytes" % ip_header.total_length
            print "\t\tIdentification:\t\t%d" % ip_header.id
            print "\t\tFlags:\t\t\t%03d\t%s" % (ip_header.flags, ip_header.flags_meaning)
            print "\t\tFragment Offset:\t%d" % ip_header.frag_offset
            print "\t\tTTL:\t\t\t%d" % ip_header.ttl
            print "\t\tProtocol:\t\t%d (%s)" % (ip_header.protocol_num, ip_header.protocol)
            print "\t\tHeader Checksum:\t0x %x" % ip_header.header_checksum
            print "\t\tSrc:\t\t\t%s" % ip_header.src_address
            print "\t\tDst:\t\t\t%s" % ip_header.dst_address

            if ip_header.protocol == "ICMP":
                # calculate where our ICMP packet starts
                # the ihl field indicates the number of 32-bit word(4byte chunks) in the ip header
                offset = 14 + (ip_header.ihl * 4)

                icmp_header = ICMP(raw_buffer[offset : offset + sizeof(ICMP)])

                print
                print "\t\tICMP >>"
                print "\t\t\tType:\t\t\t%d" % icmp_header.type
                print "\t\t\tCode:\t\t\t%d" % icmp_header.code
                print "\t\t\tChecksum:\t\t%d" % icmp_header.checksum
                print "\t\t\tUnused:\t\t\t%d" % icmp_header.unused
                print "\t\t\tNext hop:\t\t%d" % icmp_header.next_hop_mtu
                print "\t\t\tData:\t\t\t%s" % raw_buffer[offset + sizeof(ICMP):]

            if ip_header.protocol == "IGMP":
                offset = 14 + (ip_header.ihl * 4)
                igmp_header = IGMP(raw_buffer[offset : offset + sizeof(ICMP)])

                print
                print "\t\tIGMP >>"
                print "\t\t\tType:\t\t\t%s" % igmp_header.igmp_type
                print "\t\t\tMax Resp Time:\t\t%d" % igmp_header.maxRespTime
                print "\t\t\tHeader Checksum:\t0x%x" % igmp_header.header_checksum
                print "\t\t\tMulticast Addr:\t\t%s" % igmp_header.grpAddr
                if sizeof(IGMP) >> 8:
                    print "\t\t\tIGMPv3 Membership Query >> ..."

            elif ip_header.protocol == "TCP":

                offset = 14 + (ip_header.ihl * 4)
                tcp_header = TCP(raw_buffer[offset : offset + sizeof(TCP)])

                print
                print "\t\tTCP >>"
                print "\t\t\tSrc Port:\t\t%s" %  tcp_header.source_port
                print "\t\t\tDst Port:\t\t%s" %  tcp_header.destination_port
                print "\t\t\tSeq Number:\t\t0x%x" % tcp_header.sequence_number
                print "\t\t\tACK Number:\t\t0x %x" % tcp_header.acknowledgment_number
                print "\t\t\tData Offset:\t\t%d bytes" % tcp_header.data_offset
                print "\t\t\tReserved MBZ:\t\t%d" % tcp_header.reserved
                print "\t\t\t|NS |CWR|ECE|URG|ACK|PSH|RST|SYN|FIN|"
                print "\t\t\t| %d | %d | %d | %d | %d | %d | %d | %d | %d |" % (
                        tcp_header.NS,
                        tcp_header.CWR,
                        tcp_header.ECE,
                        tcp_header.URG,
                        tcp_header.ACK,
                        tcp_header.PSH,
                        tcp_header.RST,
                        tcp_header.SYN,
                        tcp_header.FIN
                        )
                print "\t\t\tWindow\t\t\t%d" % tcp_header.tcp_window
                print "\t\t\tChecksum:\t\t0x%x" % tcp_header.tcp_checksum
                print "\t\t\tUrgent Pointer:\t\t%d" % tcp_header.urgent_pointer


                if tcp_header.data_offset > 20:
                    options = raw_buffer[offset + sizeof(TCP) : offset + tcp_header.data_offset]
                    tcp_header.unpack_options(options)

                    data = raw_buffer[offset + tcp_header.data_offset:]
                    if len(data):
                        print "\t\t\tData:\t\t%d bytes" % len(data)
                        #### hexdump of data, still need to write a framework to interpret content type ####
                        # tcp_header.hexdump(data)


            # https://wiki.python.org/moin/UdpCommunication
            elif ip_header.protocol == "UDP":

                offset = 14 + (ip_header.ihl * 4)
                udp_header = UDP(raw_buffer[offset:offset+8]) # UDP header is 8 bytes

                # udp_header.hexdump(raw_buffer[offset:])

                print
                print "\t\tUDP >>"
                print "\t\t\tSrc Port:\t%d" % udp_header.src_port
                print "\t\t\tDst Port:\t%d" % udp_header.dst_port
                print "\t\t\tLength:\t\t%d" % udp_header.length
                print "\t\t\tChecksum:\t0x%x" % udp_header.checksum

                if (udp_header.src_port == 68) or (udp_header.src_port == 67):

                    dhcp_header = DHCP(raw_buffer[offset+8:offset+8+236]) # DHCP header is 236 bytes

                    print
                    print "\t\t\tDHCP >>"
                    print "\t\t\t\top:\t%d" % dhcp_header.op
                    print "\t\t\t\thtype:\t%d" % dhcp_header.htype
                    print "\t\t\t\thlen:\t%d" % dhcp_header.hlen
                    print "\t\t\t\thops:\t%d" % dhcp_header.hops
                    print "\t\t\t\txid:\t0x %x" % dhcp_header.xidd
                    print "\t\t\t\tsecs:\t%d" % dhcp_header.secs
                    print "\t\t\t\tflags:\t%d" % dhcp_header.flags
                    print "\t\t\t\tciaddr:\t%s" % dhcp_header.ciaddrr
                    print "\t\t\t\tyiaddr:\t%s" % dhcp_header.yiaddrr
                    print "\t\t\t\tsiaddr:\t%s" % dhcp_header.siaddrr
                    print "\t\t\t\tgiaddr:\t%s" % dhcp_header.giaddrr
                    print "\t\t\t\tsname:\t%s" % dhcp_header.sname # need to test if this works
                    print "\t\t\t\tfile:\t%s" % dhcp_header.bfile # need to test if this works

                    try:
                        dhcp_header.print_options(raw_buffer[offset+8+236:])
                    except:
                        print "[***Error***] : WTF, no options?!?!"

                elif (udp_header.src_port == 53) or (udp_header.dst_port == 53):

                    dns_header = DNS(raw_buffer[offset+8:offset+8+12]) # DNS header is 12 bytes or 96 bits

                    print
                    print "\t\t\tDNS >>"
                    print "\t\t\t\tIdentification:\t\t%x" % dns_header.identification
                    print "\t\t\t\tQ/R:\t\t\t%s" % dns_header.qr
                    print "\t\t\t\tOpcode:\t\t\t%s" % dns_header.Opcode
                    print "\t\t\t\tAuthoritative Answer\t%d" % dns_header.AA
                    print "\t\t\t\tTruncated\t\t%d" % dns_header.TC
                    print "\t\t\t\tRecursion Desired\t%d" % dns_header.RD
                    print "\t\t\t\tRecursion Available\t%d" % dns_header.RA
                    print "\t\t\t\tZ:\t\t\t%d" % dns_header.Z
                    print "\t\t\t\tAuthenticated Data:\t%d" % dns_header.AD
                    print "\t\t\t\tChecking Disabled:\t%d" % dns_header.CD
                    print "\t\t\t\tReturn Code:\t\t%s" % dns_header.Rcode
                    print "\t\t\t\tQuestions:\t\t%d" % dns_header.quest
                    print "\t\t\t\tAnswer RRs:\t\t%d" % dns_header.answ_RRs
                    print "\t\t\t\tAuthority RRs:\t\t%d" % dns_header.auth_RRs
                    print "\t\t\t\tAdditional RRs:\t\t%d" % dns_header.add_RRs

                    try:
                        answ = False
                        print "\t\t\t\tQueries:"
                        qoffset = raw_buffer[offset+8+12:]
                        dns_header.print_qa(qoffset, 0, answ)
                        #if dns_header.answ_RRs > 0 or dns_header.auth_RRs > 0 or dns_header.add_RRs > 0:
                        for x in range(dns_header.answ_RRs):
                            answ = True
                            print "\t\t\t\tAnswer RRs:"
                            dns_header.print_qa(qoffset, dns_header.z, answ)
                        for x in range(dns_header.auth_RRs):
                            answ = True
                            print "\t\t\t\tAuthority NS RRs:"
                            dns_header.print_qa(qoffset, dns_header.z, answ)
                        for x in range(dns_header.add_RRs):
                            answ = True
                            print "\t\t\t\tAdditional RRs:"
                            dns_header.print_qa(qoffset, dns_header.z, answ)
                    except Exception as e:
                        print e



        elif eth_header.protocol == "IPv6":
            print "\tIPv6 header class doesn't exist yet.."

        elif eth_header.protocol == "ARP":
            arp = ARP(raw_buffer[14:])
            print
            print "\tARP >>"
            print "\t\tHardware Type:\t\t%s" % arp.hrd_type
            print "\t\tProtocol Type:\t\t%s" % arp.pro_type
            print "\t\tHrd Addr Len:\t\t%d" % arp.hln
            print "\t\tProto Addr Len:\t\t%d" % arp.pln
            print "\t\tOpcode:\t\t\t%s" % arp.opcode
            print "\t\tSender Hrd Addr:\t%s" % arp.sha
            print "\t\tSender Proto Addr:\t%d.%d.%d.%d" % (arp.spa_b[0], arp.spa_b[1], arp.spa_b[2], arp.spa_b[3])
            print "\t\tTarget Hrd Addr:\t%s" % arp.tha
            print "\t\tTarget Proto Addr:\t%d.%d.%d.%d" % (arp.tpa_b[0], arp.tpa_b[1], arp.tpa_b[2], arp.tpa_b[3])

        else:
            print "\tEthernet protocol %s unknown" % eth_header.protocol

        print
        print "-------------------------------------------------------------"



except KeyboardInterrupt:
    # if we're on Windows turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
