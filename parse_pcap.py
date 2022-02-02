import argparse  # this module is for requesting and receiving arguments from the cmd
import os
import sys
from pprint import pprint  # this module is useful for printing nicely on the stdout
from scapy import all as scapy  # this module is used to parse the pcap file and returns a list of packets
from scapy.layers.inet import IP
from tabulate import tabulate  # this module is used to print iterables nicely in tables on the stdout
from collections import Counter
from datetime import datetime
import socket
from email_analysis import email_analysis
from pcap_downloads import pcap_downloads


def main():
    """ this function receives the test file from the CLI or from the default
        location and parses it using scapy"""
    global raw_data
    default_file = "evidence-packet-analysis.pcap"

    # set the parser for parsing inputs on the command line
    parser = argparse.ArgumentParser(description="Receives File name input path from the CMD line")
    parser.add_argument("--pcap", required=False, help="Input Pcap file name to parse")
    args = parser.parse_args()

    # handle exceptions
    if args.pcap and os.path.isfile(args.pcap):
        raw_data = scapy.rdpcap(args.pcap)
        print()
        print("Pcap file {) has been read successfully".format(args.pcap))
        print()

    elif not len(sys.argv) > 1:
        raw_data = scapy.rdpcap(default_file)
        print()
        print("Evidence-packet-analysis.pcap has been read successfully")
        print()

    else:
        print(str(format(args.pcap)) + " " + "does not exist", file=sys.stderr)
        sys.exit(-1)


main()


def parse_pcap():
    """"this function conducts the operations involving the packets
         and returns analysed data about them"""
    # The traffic list will contain a list of protocols with  info in a list
    global traffic
    traffic = []

    # the all_packets list has to be accessible throughout the program hence we use function objects
    parse_pcap.all_packets = []

    # initialise a packet counter  # the len() function can also be used
    # to get the number of packets in a list
    all_packet_count = 0

    # initialize a list and dict to store the lengths of each packet
    parse_pcap.packet_length = {}
    parse_pcap.packet_length_list = []

    # initialise all ip pairs and ip pair list
    all_ip_pairs = []

    # Initialize a list of all IP addresses
    parse_pcap.destination_ip_addresses = []

    # ip pair index counter
    ip_pair_index = -1

    # define the format for the time stamps
    time_format = '%m/%d/%y %H:%M:%S:%f'

    # create a dictionary of lists to store the packets of each particular protocol
    protocol_dict = {}

    # check for all possible IP protocols from the socket library
    # and convert the protocol number to the corresponding protocol name
    protocols = {}
    for name, number in vars(socket).items():
        if name.startswith("IPPROTO"):
            protocol_name = name[8:]
            protocol_number = number

            # store the protocol numbers and names to the protocol dictionary
            protocols[str(protocol_number)] = protocol_name
        else:
            continue

    # dynamically create protocol_packet lists that will store packets of each protocol
    # to do this, globals is used to assign variable names dynamically for each protocol that we find
    for protocol_number, protocol_name in protocols.items():
        # dynamic lists are created for each protocol
        globals()[f'{protocol_name}_packets'] = []

        # The traffic type lists contain various data about packets of particular protocol
        globals()[f'{protocol_name}'] = [str(protocol_name)]

        # append the different lists of each type of packet to the traffic list
        traffic.append(globals()[f'{protocol_name}'])

        # initialize lists to store lengths of packets in each protocol
        globals()[f'{protocol_name}_packet_length'] = []

    # iterate through the list of packets to retrieve their IP addresses, check the type and count the number
    for packet in raw_data:
        # store packets in the packet list
        parse_pcap.all_packets.append(packet)

        # increment the all packet counter for each packet iterated
        all_packet_count += 1

        # retrieve the source ip address of each packet # i could do that
        if IP in packet:
            ip_pair = []
            source_ip_address = packet[IP].src
            ip_pair.append(source_ip_address)

        # retrieve the destination ip address
            destination_ip_address = packet[IP].dst
            parse_pcap.destination_ip_addresses.append(destination_ip_address)
            ip_pair.append(destination_ip_address)
            ip_pair_index += 1
            all_ip_pairs.append(ip_pair)

        # find the length of the packet
            length = len(packet)
            parse_pcap.packet_length[destination_ip_address] = length
            parse_pcap.packet_length_list.append(length)

        # 1. retrieve the assigned protocol values  from each packet
        protocol_value = packet.payload.proto
        # 2. use the protocol values to identify packets with particular protocol type
        for protocol_number, protocol_name in protocols.items():
            if int(protocol_number) == int(protocol_value):
                # append the packets to the particular packets list
                globals()[f'{protocol_name}_packets'].append(packet)

                # find the length of each packet and store values to list
                globals()[f'{protocol_name}_packet_length'].append(len(packet))

    # Count the number of packets involved in each Ip address pair
    parse_pcap.count = Counter(str(e) for e in all_ip_pairs)

    # store the packets and their number to respective datastructures for each protocol
    for protocol_number, protocol_name in protocols.items():
        # protocol packet count
        globals()[f'{protocol_name}_packet_count'] = len(globals()[f'{protocol_name}_packets'])

        # check if there were packets of a protocol found and operate with those found
        if len(globals()[f'{protocol_name}_packets']) != 0:
            # append the packet count to the protocol list
            globals()[f'{protocol_name}'].append(globals()[f'{protocol_name}_packet_count'])

            # append the lists storing packets to a protocol_dict dictionary with teh protocol name as the key
            protocol_dict[str(protocol_name)] = globals()[f'{protocol_name}_packets']


    "modified from https://stackoverflow.com/questions/5522031/convert-timedelta-to-total-seconds"
    # this operation converts the timestamps to human readable dates and time
    for protocol_number, protocol_name in protocols.items():
        if len(globals()[f'{protocol_name}_packets']) != 0:
            # find and append the first and last time stamps
            # first timestamp
            globals()[f'first_{protocol_name}_packet'] = globals()[f'{protocol_name}_packets'][0]
            globals()[f'first_{protocol_name}_timestamp'] = globals()[f'first_{protocol_name}_packet'].time

            # last timestamp
            globals()[f'last_{protocol_name}_index'] = len(globals()[f'{protocol_name}_packets']) - 1
            globals()[f'last_{protocol_name}_packet'] = globals()[f'{protocol_name}_packets'][globals()[f'last_{protocol_name}_index']]
            globals()[f'last_{protocol_name}_timestamp'] = globals()[f'last_{protocol_name}_packet'].time

            # format the timestamps to human-readable date and time formats
            globals()[f'first_{protocol_name}_timestamp'] = datetime.fromtimestamp(globals()[f'first_{protocol_name}_timestamp'])
            globals()[f'last_{protocol_name}_timestamp'] = datetime.fromtimestamp(globals()[f'last_{protocol_name}_timestamp'])
            globals()[f'first_{protocol_name}_timestamp'] = globals()[f'first_{protocol_name}_timestamp'].strftime('%x %X:%f')
            globals()[f'last_{protocol_name}_timestamp'] = globals()[f'last_{protocol_name}_timestamp'].strftime('%x %X:%f')
            globals()[f'first_{protocol_name}_timestamp'] = datetime.strptime(globals()[f'first_{protocol_name}_timestamp'], time_format)
            globals()[f'last_{protocol_name}_timestamp'] = datetime.strptime(globals()[f'last_{protocol_name}_timestamp'], time_format)

            # append
            globals()[f'{protocol_name}'].append(globals()[f'first_{protocol_name}_timestamp'])
            globals()[f'{protocol_name}'].append(globals()[f'last_{protocol_name}_timestamp'])

            # find the total packet length and assign to respective key in TCP dict
            # sum the lengths of all the packets
            globals()[f'total_{protocol_name}_packet_length'] = 0
            for length in globals()[f'{protocol_name}_packet_length']:
                globals()[f'total_{protocol_name}_packet_length'] += length

            # Calculate and append mean packet length
            globals()[f'mean_{protocol_name}_packet_length'] = globals()[f'total_{protocol_name}_packet_length'] / globals()[f'{protocol_name}_packet_count']
            globals()[f'{protocol_name}'].append(globals()[f'mean_{protocol_name}_packet_length'])


parse_pcap()


#
def output():
    """"The function below outputs the analysed data"""
    # output in a table
    no_of_packets = str(len(raw_data))
    print("The file has" + " " + no_of_packets + " " + "packets")
    print(" ")
    header = ['Type', 'Number of Packets', 'First timestamp', 'last timestamp', 'Mean packet length']
    print(tabulate(traffic, headers=header, tablefmt='orgtbl'))


# Print Ip traffic
    print(''.center(50, '-'))
    count_str = "The following are the number of packets involved in each IP pair"
    print()
    print(str(count_str).center(40, '-'))
    pprint(parse_pcap.count)
    print(''.center(40, '-'))

# print email address results
    to_str = "To email addresses"
    print(to_str.center(40, '-'))
    pprint(email_analysis.to_emails)
    print(''.center(40, '-'))
    print()

    from_str = "From email addresses"
    print(str(from_str).center(40, '-'))
    pprint(email_analysis.from_emails)
    print('-'.center(40, '-'))

    # print Image operation results
    print()
    print('Image get urls'.center(40, '-'))
    pprint(pcap_downloads.image_url_list)
    print('-'.center(40, '-'))
    print()
    print('Image file names'.center(40, '-'))
    pprint(pcap_downloads.file_names_list)
    print('-'.center(40, '-'))
