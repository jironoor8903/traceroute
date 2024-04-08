import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3


SELECT_TIMEOUT = 2  # Timeout for select call, as defined in util

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
    # reference : https://www.youtube.com/watch?v=IozUoCVbLeI
        self.version = buffer[0] >> 4
        # get last 4 bits of the 0th byte
        self.header_len = (buffer[0] & 0x0F)
        self.header_len = self.header_len * 4
        self.tos = buffer[1]
        self.length = int.from_bytes(buffer[2:4], 'big')
        self.id = int.from_bytes(buffer[4:6], 'big')
        self.flags = buffer[6] >> 5
        self.frag_offset = int.from_bytes(buffer[6:8], 'big') & 0x1FFF
        self.ttl = buffer[8]
        self.proto = buffer[9]
        self.cksum = int.from_bytes(buffer[10:12], 'big')
        
        # Source IP Address
        src_bytes = buffer[12:16]
        src_parts = []
        for x in src_bytes:
            src_parts.append(str(x))
        self.src = '.'.join(src_parts)

        # Destination IP Address
        dst_bytes = buffer[16:20]
        dst_parts = []
        for x in dst_bytes:
            dst_parts.append(str(x))
        self.dst = '.'.join(dst_parts)

                    

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        self.type = buffer[0]
        self.code = buffer[1]
        self.cksum = int.from_bytes(buffer[2:4], 'big')

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        self.src_port = int.from_bytes(buffer[0:2], 'big')
        self.dst_port = int.from_bytes(buffer[2:4], 'big')
        self.len = int.from_bytes(buffer[4:6], 'big')
        self.cksum = int.from_bytes(buffer[6:8], 'big')

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Your code here
    routers = []
    destination_reached = False

    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        sendsock.set_ttl(ttl)
        ttl_routers = set()
        response = set()
        for i in range(PROBE_ATTEMPT_COUNT):
            sendsock.sendto(b'', (ip, TRACEROUTE_PORT_NUMBER))

            while recvsock.recv_select():
                buf, address = recvsock.recvfrom()
                if len(buf) < 20:
                    continue
                ip_header = IPv4(buf[:20]) 
                
                if buf not in response:
                    response.add(buf)
                # Check if the response is ICMP Time Exceeded or Port Unreachable
                if len(buf) >= ip_header.header_len + 8: 
                    if ip_header.proto == 1:
                        icmp_header = ICMP(buf[ip_header.header_len:])
                        if icmp_header.type == 11 and icmp_header.code == 0:  # ICMP Time Exceeded
                            ttl_routers.add(address[0])
                            print(f"ttl: {ttl} router address: {address[0]}")
                            print(f"ipv4header src: {ip_header.src}")
                        elif icmp_header.type == 3 and icmp_header.code == 3:  # Port Unreachable
                            ttl_routers.add(address[0])
                            print(f"ttl: {ttl} router address: {address[0]}")
                            print(f"ipv4header src: {ip_header.src}")
                            destination_reached = True
                            break
        # print(ttl)
        # print(list(ttl_routers))
        routers.append(list(ttl_routers))
        # util.print_result(list(ttl_routers), ttl)
        if destination_reached:
            break
    print(routers)
    return routers


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)


