#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
import binascii

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)              

def switch_setup(switch_id):
    file = open('./configs/switch' + switch_id + '.cfg', 'r')

    priority = int(file.readline().strip())

    vlans = {}
    i = 0
    for line in file:
        interface, vlan = line.split()
        vlans[i] = (interface, vlan, "")
        i += 1
    
    return priority, vlans

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    priority, vlans = switch_setup(switch_id)

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    mac_table = {}

    t = threading.Thread(target=send_bdpu_every_sec, args=(priority, vlans, get_switch_mac()))
    t.start()

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')            # send it only if the interface vlan is the same as the vlan of the frame
            # or if the interface is a trunk
        print(f'EtherType: {ethertype}')
        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        dest_mac_bytes = binascii.unhexlify(dest_mac.replace(':', ''))

        if dest_mac == "01:80:c2:00:00:00":
            continue
        else:
            mac_table[src_mac] = interface

            if (dest_mac_bytes[0] & 0x01) == 0:
                if dest_mac in mac_table:
                    if(vlan_id == -1):
                        name_dest, vlan_dest, state_dest = vlans[mac_table[dest_mac]]
                        for i in vlans:
                            name, vlan, state = vlans[i]
                            if i == interface:
                                vlan_id = int(vlan)
                                break
                        if vlan_dest == 'T' and state_dest != "BLOCKED":
                            vlan_data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                            send_to_link(mac_table[dest_mac], length + 4, vlan_data)
                        elif int(vlan_dest) == vlan_id:
                            send_to_link(mac_table[dest_mac], length, data)
                    else:
                        name_dest, vlan_dest, state_dest = vlans[mac_table[dest_mac]]
                        if vlan_dest == 'T' and state_dest != "BLOCKED":
                            send_to_link(mac_table[dest_mac], length, data)
                        elif int(vlan_dest) == vlan_id:
                            vlan_data = data[0:12] + data[16:]
                            send_to_link(mac_table[dest_mac], length - 4, vlan_data)
                else:
                    if(vlan_id == -1):
                        for i in vlans:
                            name, vlan, state = vlans[i]
                            if i == interface:
                                vlan_id = int(vlan)
                                break
                        for i in vlans:
                            name, vlan, state = vlans[i]
                            if vlan == 'T' and i != interface and state != "BLOCKED":
                                vlan_data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                                send_to_link(i, length + 4, vlan_data)
                            elif i != interface and int(vlan) == vlan_id:
                                send_to_link(i, length, data)
                    else:
                        for i in vlans:
                            name, vlan, state = vlans[i]
                            if vlan == 'T' and i != interface and state != "BLOCKED":
                                send_to_link(i, length, data)
                            elif i != interface and int(vlan) == vlan_id:
                                vlan_data = data[0:12] + data[16:]
                                send_to_link(i, length - 4, vlan_data)
            else:
                if(vlan_id == -1):
                    for i in vlans:
                        name, vlan, state = vlans[i]
                        if i == interface:
                            vlan_id = int(vlan)
                            break
                    for i in vlans:
                        name, vlan, state = vlans[i]
                        if vlan == 'T' and i != interface and state != "BLOCKED":
                            vlan_data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                            send_to_link(i, length + 4, vlan_data)
                        elif i != interface and int(vlan) == vlan_id:
                            send_to_link(i, length, data)
                else:
                    for i in vlans:
                        name, vlan, state = vlans[i]
                        if vlan == 'T' and i != interface and state != "BLOCKED":
                            send_to_link(i, length, data)
                        elif i != interface and int(vlan) == vlan_id:
                            vlan_data = data[0:12] + data[16:]
                            send_to_link(i, length - 4, vlan_data)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()

