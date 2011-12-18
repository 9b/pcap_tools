#!/usr/bin/python

__description__ = 'Summarize a PCAP file'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/12/1'

from libs.c2utils import pcap_miner
import time, re, optparse, getpass, time, hashlib, os

def generate(infile, outfile):
    miner = pcap_miner(infile)
    #file 1 - DNS queries and domains returned
    f = open(outfile + "dns_queries.txt","w")	
    for dns in miner.get_dns_request_data():
        f.write(dns['type'] + " - " + dns['request'] + " - " + dns['response'] + "\n")	
    f.close()

    #file 2 - IPS of attackers without whois
    f = open(outfile + "attacker_ips.txt","w")
    for ip in miner.get_destination_ips():
        f.write(ip + "\n")
    f.close()

    #file 3 - IPs of attackers with whois 
    f = open(outfile + "attacker_ips_whois.txt","w")	
    for ip in miner.get_destination_ip_details():
        f.write(ip['ip_address'] + " - " + ip['owner'] + " - " + ip['asn'] + " - " + ip['block'] + "\n")	
    f.close()

    #file 4 - what you called HTTPrequests but it can be other port just the requests back forh part
    f = open(outfile + "http_requests.txt","w")
    for info in miner.get_http_request_data():
        if 'user-agent' not in info:
            info['user-agent'] = " "

        f.write(info['source_ip'] + " - " + info['destination_ip'] + " - " + info['method'] + " - " + info['user-agent'] + " - " + info['uri'] + "\n")
    f.close()

    #file 5 - whatever can be dumped from the request
    f = open(outfile + "full_http_requests.txt","w")
    for info in miner.get_http_request_data():
        for key, value in info.items():
            f.write(key + " - " + value + "\n")
        f.write("\n")
    f.close()

    #file 6 - dump flows
    f = open(outfile + "flows.txt","w")
    for info in miner.get_flows():
        f.write(info + "\n")
    f.close()

def main():
    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-f', '--file', type='string', help='input PCAP file for processing')
    oParser.add_option('-d', '--dir', type='string', help='input PCAP dir for processing')
    oParser.add_option('-o', '--out', type='string', help='output directory - absolute path only')
    oParser.add_option('-v', '--verbose', action="store_true", default=False, help='verbose logging on performed actions')
    (options, args) = oParser.parse_args()

    if options.file and options.out:
        generate(options.file,options.out)
    elif options.dir and options.out:
        files = []
        dirlist = os.listdir(options.dir)
        for fname in dirlist:
            files.append(fname)
        files.sort()
        count = 0

        for file in files:	
            outdir = options.out + hashlib.md5(file).hexdigest() + "/"
            if not os.path.exists(outdir):
                os.makedirs(outdir)	    
            generate(options.dir + file,outdir)
    else:
        oParser.print_help()
        return

if __name__ == '__main__':
    main()
