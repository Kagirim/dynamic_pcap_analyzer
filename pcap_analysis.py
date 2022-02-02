import json
from pip._vendor import requests
from parse_pcap import parse_pcap


def pcap_analysis():
    """"this function retrieves destination ip addresses
        and searches for geological information on geological_db API"""
    # initialize the geoinfo dict
    pcap_analysis.geoinfo = {}
    # IP address to test
    pcap_analysis.destination_ip_addresses = parse_pcap.destination_ip_addresses

    # remove duplicates
    destination_ip_set = set(pcap_analysis.destination_ip_addresses)
    pcap_analysis.destination_ip_addresses = list(destination_ip_set)

    # initialize a dictionary of the count of the packets in each destination ip address
    parse_pcap.destination_ip_packet_count = {}

    # initialize a counter for the number of packets in each destination ip address
    destination_ip_packet_counter = 0

    # create a list of valid ip addresses (those that the API has found a geolocation for)
    pcap_analysis.valid_destination_ip_addresses = []

    # create a list to store the locations in terms of latitude and longitude
    pcap_analysis.locations = []

    for dst_ip in pcap_analysis.destination_ip_addresses:
        # IP address to test
        ip_address = dst_ip
        request_url = 'https://geolocation-db.com/jsonp/' + ip_address

        # Send request and decode the result
        response = requests.get(request_url)
        result = response.content.decode()

        # Clean the returned string so it just contains the dictionary data for the IP address
        result = result.split("(")[1].strip(")")

        # Convert this data into a dictionary)
        result = json.loads(result)

        # handle exceptions
        if result['country_name'] != "Not found":
            # remove unwanted values
            result.pop('country_code')
            result.pop('postal')
            result.pop('IPv4')
            result.pop('state')
            # add the destination IP address to the dictionary
            pcap_analysis.geoinfo[dst_ip] = result

            # append to the list of valid destination ip addresses
            pcap_analysis.valid_destination_ip_addresses.append(dst_ip)

            # count the number of packets for each destination IP address
            destination_ip_packet_counter += 1
            parse_pcap.destination_ip_packet_count[dst_ip] = destination_ip_packet_counter

            # store the latitudes and longitudes
            lat_long = [dst_ip, result['latitude'], result['longitude']]
            pcap_analysis.locations.append(lat_long)



