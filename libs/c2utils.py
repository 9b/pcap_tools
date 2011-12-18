import socket
import itertools
import operator

try:
	import dpkt
except:
	print "Download dpkt"

try:
	import cymruwhois
except:
	print "Download cymruwhois"

class pcap_miner():
    def __init__(self,pcap_file):
        #declaration
        self._pcap_file = pcap_file
        self._http_request_data = []
        self._source_ips = []
        self._destination_ips = []
        self._source_ip_details = []
        self._destination_ip_details = []
        self._dns_request_data = []
        self._flows = []
        self._packet_count = 0
        self._http_count = 0
        self._dns_count = 0
        
        #processing
        self._handle = self._get_dpkt_handle()
        self._extract_data()
        
    def _get_dpkt_handle(self):
        f = open(self._pcap_file)
        pcap = dpkt.pcap.Reader(f)
        return pcap
    
    def unpack_ip(self,packed_ip):
        ip = socket.inet_ntoa(packed_ip)
        return ip

    def quick_unique(self,seq):
        seen = set()
        return [ x for x in seq if x not in seen and not seen.add(x)]
    
    def _extract_data(self):
        pcap = self._handle
        eth = None
        ip = None
        protocol = None

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                protocol = ip.data
            except dpkt.dpkt.NeedData:
                continue
            
            self._packet_count += 1
            
            try:
                source_ip = self.unpack_ip(ip.src)
                destination_ip = self.unpack_ip(ip.dst)
                self._source_ips.append(source_ip)
                self._destination_ips.append(destination_ip)
            except Exception, e:
                continue
            
            try:
                if protocol.dport == 80 or protocol.dport == 443:
                    self._http_count += 1
                    try:
                        http = dpkt.http.Request(protocol.data)
                        tmp = http.headers
                        tmp["source_ip"] = source_ip
                        tmp['destination_ip'] = destination_ip
                        tmp['method'] = http.method
                        tmp['version'] = http.version
                        tmp['uri'] = http.uri
                        self._http_request_data.append(tmp)
                    except Exception, e:
                        continue
            except Exception, e:
                continue
                
            try:
                if protocol.dport == 53 or protocol.sport == 53:
                    self._dns_count += 1
                    try:
                        dns = dns = dpkt.dns.DNS(protocol.data)
                        if dns.qr != dpkt.dns.DNS_R: continue
                        if dns.opcode != dpkt.dns.DNS_QUERY: continue
                        if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
                        if len(dns.an) < 1: continue
                        for answer in dns.an:
                            if answer.type == 5:
                                tmp = { "type": "CNAME", "request":answer.name, "response":answer.cname }
                                self._dns_request_data.append(tmp)
                            elif answer.type == 1:
                                tmp = { "type": "A", "request":answer.name, "response":socket.inet_ntoa(answer.rdata) }
                                self._dns_request_data.append(tmp)
                            elif answer.type == 12:
                                tmp = { "type": "PTR", "request":answer.name, "response":answer.ptrname }
                                self._dns_request_data.append(tmp)

                    except Exception, e:
                        continue
            except Exception, e:
                continue
            try:
                self._flows.append(source_ip + "/" + destination_ip + "/" + str(protocol.dport))
            except Exception, e:
                continue
                                   
    def get_source_ips(self):
        return self.quick_unique(self._source_ips)
    
    def get_source_ip_details(self):
        ulist = self.quick_unique(self._source_ips)
        c = cymruwhois.Client()
        for item in c.lookupmany(ulist):
            try:
                if item.prefix == None:
                    tmp = { "ip_address": item.ip, "block": "", "asn": "", "owner": "" }
                else:
                    tmp = { "ip_address": item.ip, "block": item.prefix, "asn": item.asn, "owner": item.owner }
                self._source_ip_details.append(tmp)
            except Exception, e:
                continue
                
        return self._source_ip_details
                
    def get_destination_ips(self):
        return self.quick_unique(self._destination_ips)
    
    def get_destination_ip_details(self):
        ulist = self.quick_unique(self._destination_ips)
        c = cymruwhois.Client()
        for item in c.lookupmany(ulist):
            try:
                if item.prefix == None:
                    tmp = { "ip_address": item.ip, "block": "", "asn": "", "owner": "" }
                else:
                    tmp = { "ip_address": item.ip, "block": item.prefix, "asn": item.asn, "owner": item.owner }
                self._destination_ip_details.append(tmp)
            except Exception, e:
                continue
                
        return self._destination_ip_details
    
    def get_http_request_data(self):
        getvals = operator.itemgetter('source_ip','destination_ip', 'uri')
        self._http_request_data.sort(key=getvals)

        result = []
        for k, g in itertools.groupby(self._http_request_data, getvals):
            result.append(g.next())

        self._http_request_data[:] = result
        return self._http_request_data
    
    def get_dns_request_data(self):
        getvals = operator.itemgetter('type','request', 'response')
        self._dns_request_data.sort(key=getvals)

        result = []
        for k, g in itertools.groupby(self._dns_request_data, getvals):
            result.append(g.next())

        self._dns_request_data[:] = result
        return self._dns_request_data
                
    def get_flows(self):
        return self.quick_unique(self._flows)
    
    def get_packet_count(self):
        return self._packet_count
    
    def get_http_count(self):
        return self._http_count
    
    def get_dns_count(self):
        return self._dns_count
