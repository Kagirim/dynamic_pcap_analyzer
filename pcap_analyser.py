import yaml  # this module is suitable to print nested dictionaries nicely
from parse_pcap import output
from pcap_kml import pcap_kml
from pcap_kml import traffic_graph
from pcap_analysis import pcap_analysis


if __name__ == "__main__":
    """output all the data analysed from the test pcap file"""
    output()

    pcap_analysis()

    # print the geoinfo nicely using yaml
    print()
    geoinfo_str = "The Geoinfo for the unique destination IP addresses"
    print()
    print(geoinfo_str.center(40, '-'))
    print(yaml.dump(pcap_analysis.geoinfo))

    pcap_kml()

    traffic_graph()
