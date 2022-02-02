import re
from email_analysis import email_analysis


def pcap_downloads():
    """"retrieve the raw payload data from the email analysis file"""
    raw_layers = email_analysis.raw_layers

    # find the img, jpg files from the raw payload data using regex
    "help from https://www.oreilly.com/library/view/effective-python-penetration/9781785280696/ch02.html (Rejah Rehim)"
    img_urls = re.findall(r'https?://(?:[a-z0-9\-]+\.)[a-z]{2,6}(?:/[^/#?]+)+\.(?:jpg|gif|png)', str(raw_layers))

    # Initialize the lists to store the values retrieved from the operation
    pcap_downloads.image_url_list = []
    pcap_downloads.file_names_list = []

    # extract the image urls from the packet get requests
    for line in img_urls:
        # convert the extracted line into a string
        line_string = str(line)
        # print(line_string)

        # split the lines into individual words
        words = line_string.split()

        # get the index of the last word
        number_of_words = len(words)
        last_word = number_of_words - 1

        # Get only the first and last words and remove unwanted characters
        first_url_section = words[0]
        first_url_section_string = "".join(words[0])
        first_url_section = re.findall("http[s]?://+[a-z.a-z]*", first_url_section_string)
        first_url_section = "".join(first_url_section)

        # get the last word using the number of words
        last_url_section = words[last_word]
        last_url_section = "".join(words[last_word])

        # get image file names
        file_names = re.findall("[a-zA-Z0-9-_]*.(?:jpg|gif|png)", last_url_section)
        file_names = "".join(file_names)
        pcap_downloads.file_names_list.append(file_names)

        # join the first and end sections to get the whole ulr
        complete_ulr = str(first_url_section) + str(last_url_section)
        # print(complete_ulr)

        # store the image urls in a list
        pcap_downloads.image_url_list.append(complete_ulr)


pcap_downloads()
