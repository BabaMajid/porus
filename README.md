# porus

**Online IP Checking in Bulk from Virus Total and OTX.**

Name porus came from famous Indian king from Punjab who had the courage to fight Alexander near river Jehlum.

Porus is IPs reputation checking script from TI platforms like VT and OTX in bulk.
It can accept input in form of [pcap, csv, txt] and generate the results in xlsx file by quering OTX and VT.

To make it work you need to have OTX and Virus Total API key.

Help:

usage: porus.py [-h] [-f INPUT_FILE] [-o OUTPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --file INPUT_FILE
  -o OUTPUT_FILE, --output OUTPUT_FILE

   Description : Porus can parse pcap file and get IPs reputation from VT and OTX. You need to provide VT and OTX api key in **config.ini** file.
    config.ini file need to be in the same directory as porus.py.
    
    Author: Majid Jahangeer
    Email: mianmajid432@gmail.com
    Version: 1.1
    Usage : python porus.py -i sample.pcap -o sample.xlsx
            python porus.py -i ips.txt -o sample.xlsx
            python porus.py -i ips.csv -o results.xlsx
