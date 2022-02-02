import simplekml  # this module makes kml files and allows us to plot coordinates
from parse_pcap import parse_pcap
from pcap_analysis import pcap_analysis
from datetime import datetime
from matplotlib import pyplot as plt
import statistics


def pcap_kml():
    """"this function stores the city and packet count values of
    each unique destination IP address in a KML file"""
    # open kml file
    "help from http://fredgibbs.net/tutorials/create-kml-file-python.html (ripper234)"
    kml = simplekml.Kml()

    locations = pcap_analysis.locations

    for location in locations:
        kml.newpoint(name=location[0], coords=[(location[2], location[1])])

    # save the kml file as geoinfomation.kml
    return kml.save('geoinfomation.kml')


def traffic_graph():
    # matplotlib operations
    # find the time of each packet
    packets = {}
    packet_index = -1
    time = []
    raw_time_list = []
    all_packets = parse_pcap.all_packets

    # declare the time format to be used
    time_format = '%H:%M:%S:%f'

    for packet in all_packets:
        packet_index += 1

        # get the time for each packet
        packet_time = packet.time
        raw_time = packet.time

        # format the time
        packet_time = datetime.fromtimestamp(packet_time)
        packet_time = packet_time.strftime('%X:%f')
        packet_time = datetime.strptime(packet_time, time_format)

        # append time
        time.append(packet_time)
        raw_time_list.append(raw_time)

        # append the time to the time dictionary with the packet index as the key
        packets[packet_index] = packet_time

    # get first and last timestamps
    first_time = time[0]
    last_time = time[len(time) - 1]

    # subtract the first and last timestamps to get length of time
    time_length = last_time - first_time

    # get 10 time intervals
    intervals = []
    time_interval = time_length/
    interval_range_list = []
    for i in range(20):
        first_time = first_time + time_interval
        interval_end_time = first_time

        # store the values in a list
        intervals.append(interval_end_time)

        # store the ranges in a list
        start_time = interval_end_time - time_interval
        interval_range = [start_time, interval_end_time]
        interval_range_list.append(interval_range)

    # count the number of packets in each time interval
    packet_count_list = []
    for interval in interval_range_list:
        start_time = interval[0]
        end_time = interval[1]
        new_list = []
        for t in time:
            if start_time <= t <= end_time:
                new_list.append(t)
        packet_count_list.append(new_list)

    # calculate number of packets per interval
    packet_count = []
    for number_of_packets in packet_count_list:
        packet_count.append(len(number_of_packets))

    # find the threshold
    mean = statistics.mean(packet_count)
    threshold = mean + 2

    # Plot packets against time
    # y will plot the number of packets for each interval
    y = packet_count

    # x will plot the even time length intervals
    x = intervals
    plt.plot(x, y)

    # t will plot the threshold
    plt.axhline(threshold, color='red', linestyle='--')

    # label the axes
    plt.xlabel('time')
    plt.ylabel('number of packets')
    plt.title('Graph plotting time against the number of packets')

    # display the graph
    plt.show()

    # save the graph to image
    plt.savefig('packetstime.png')
