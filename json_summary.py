
#!/usr/bin/python

__description__ = 'Summarize a PCAP file to standard out'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/12/1'

from libs.c2utils import pcap_miner
import time, re, optparse, getpass, time

def main():
    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-f', '--file', type='string', help='input PCAP file for processing')
    oParser.add_option('-v', '--verbose', action="store_true", default=False, help='verbose logging on performed actions')
    (options, args) = oParser.parse_args()

    if options.file:
        miner = pcap_miner(options.file)
        print miner.summary2json()

    else:
        oParser.print_help()
        return

if __name__ == '__main__':
    main()
