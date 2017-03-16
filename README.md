# What 7 this?
- This is just a school project that about "SDN security", which means...
    -  the code are messy and unreadable.
    -  do not expect has good performance
    -  many bugs

# Description
## read this first
- I am using the RYU controller in this project.
- All the experiments test in the Mininet VM
- I mainly aim to detect the following malicious traffics in SDN:
    - Scanning probe traffics like nmap, ncat or maybe telnet for HTTP
    - "Potential flooding" - it is a rubbish because I just set a threshold manually in ```simple_monitor_13.py``` for flow stat and port stat for the detection
- Currently, I only upload the parser coding for convert pcap to csv
- I will upload the codes of RYU later in May after the final presentation
## folder structure in this repo
- ```pcap_parsing_and_data_training/``` store the code of pcap parser and the ML code for training the clf(classifiers). Those clf are used in RYU later
- ```ryu_code/``` store the ryu controller codes, there will be only 2 files ```example_switch_13.py``` & ```simple_monitor_13.py```

