import socket
import sys
import struct
import time

def main():
    # Bind to UDP 37008 to catch the TZSP stream from the router
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 37008))
    
    # IMPORTANT: 5-second timeout to fix Zeek's offline clock freeze
    sock.settimeout(5.0)
    
    # Write the Global PCAP Header to stdout
    # Magic Number: 0xa1b2c3d4 (Big-Endian)
    # Version: 2.4, Snaplen: 65535, Network: 1 (Ethernet)
    pcap_header = struct.pack("!IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    sys.stdout.buffer.write(pcap_header)
    sys.stdout.buffer.flush()
    
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            
            # TZSP Format:
            # 1 Byte Version (1)
            # 1 Byte Type (0 = Received)
            # 2 Bytes Protocol (1 = Ethernet)
            if len(data) < 5:
                continue
                
            idx = 4
            # Traverse TZSP tags until we hit the END tag (0x01)
            while idx < len(data):
                tag_type = data[idx]
                if tag_type == 1: # END of tags
                    idx += 1
                    break
                idx += 1
                if idx < len(data):
                    tag_len = data[idx]
                    idx += 1 + tag_len
                    
            if idx >= len(data):
                continue
                
            # The remaining payload is the pure inner Ethernet frame
            eth_frame = data[idx:]
            
        except socket.timeout:
            # Zeek "offline clock freeze" workaround:
            # If 5 seconds pass with no real traffic, send a dummy packet.
            # 14 bytes: ff:ff:ff:ff:ff:ff (dst), ff:ff:ff:ff:ff:ff (src), 0x0000 (type)
            eth_frame = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00"
            
        except Exception as e:
            continue
            
        # Generate Packet PCAP Header
        t = time.time()
        ts_sec = int(t)
        ts_usec = int((t - ts_sec) * 1000000)
        pkt_len = len(eth_frame)
        
        pkt_header = struct.pack("!IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        
        # Stream the packet to Zeek
        sys.stdout.buffer.write(pkt_header)
        sys.stdout.buffer.write(eth_frame)
        sys.stdout.buffer.flush()

if __name__ == "__main__":
    main()
