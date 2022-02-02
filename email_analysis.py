from scapy import all as scapy
import re

def email_analysis():
    """"this function parses the payload layer of the packet and retrieves
        emails using regular expressions"""
    payloads = []
    email_analysis.raw_layers = []
    all_emails = []
    from_to_emails = []

    raw_data = scapy.rdpcap("evidence-packet-analysis.pcap")
    for packet in raw_data:
        payload = packet.payload
        payloads.append(payload)
        # packet.show()

        # get the Raw layer from the packet sorry i think is repetition
        raw_layer = packet.getlayer('Raw')

        email_analysis.raw_layers.append(raw_layer)

        # find the email addresses
    email_analysis.from_emails = re.findall(r'\S[From]+[a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+',
                                            str(email_analysis.raw_layers))
    email_analysis.to_emails = re.findall(r'\S[To]+[a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+',
                                          str(email_analysis.raw_layers))

    # append the lists to a common list
    all_emails.append(email_analysis.from_emails)
    all_emails.append(email_analysis.to_emails)

    # Operation to remove duplicates using sets
    if len(all_emails) != 0:
        to_email_set = set(email_analysis.to_emails)
        from_email_set = set(email_analysis.from_emails)

        # new_from_list = list(new_from_list)
        # new_to_list = list(new_to_list)

        from_to_emails.append(from_email_set)
        from_to_emails.append(to_email_set)


email_analysis()
