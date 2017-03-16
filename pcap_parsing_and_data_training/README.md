# Description
- All the coding are very messy
- All the coding are written in Jupyter notebook initially, I just saved them as ```.py``` file
- The parser is only working for parsing ```TCP``` and ```HTTP``` currently, other protocols not implement yet.

# Directory structure
    +---pcap/
    |    \--- pre_process_add_label.py # for parse the PCAP file to csv/ in csv format
    |    \--- some sample.pcap # specify its name in pre_process_add_label.py for parsing
    +---csv/
    |    \---set of parsed .csv files
    |    \---pre_process_add_label.py # label the parsed csv manually and save in 'labeled_dataset/'
    +    \---labeled_dataset/
            \---labeled csv files ready for data training
            \---tcp_data_training.py # traing the clf for TCP
            \---DPI_HTTP_training.py # traing the clf for HTTP
            \---html/ # html gen by jupyter notebook for ref.
            \---clf/  # trained classifiers
