import dns.resolver
import dns.reversename
import ipaddress
import sys
import argparse

ipcdns = ['148.173.250.189', '148.173.129.21']
gsodns = ['148.173.250.45', '148.173.250.189']

domain_servers = dict(
    americas_east = ['10.21.12.85', '10.21.12.86', '148.173.250.27'], 
    americas_west = ['148.173.250.201', '148.173.250.27', '10.21.12.85'], 
    emea_east = ['10.21.32.10', '164.12.33.23', '10.21.12.86'], 
    emea_west = ['164.12.33.23', '10.21.32.10', '10.21.12.86'], 
    lac = ['148.173.52.238', '10.21.1.85', '148.173.250.27'], 
    japa_south = ['148.172.200.46', '148.172.160.50', '148.172.134.186'], 
    japa_north = ['148.172.150.60', '148.172.134.186', '148.172.200.46']
)

print domain_servers

my_resolver = dns.resolver.Resolver()
my_resolver.nameservers = ipcdns
my_resolver.timeout = 1

MAX_IP_LEN = len('XXX.XXX.XXX.XXX')

def dns_reverse_lookup(subnet):

    for ip in subnet:
        try:
            ip = ip.exploded
            reversename = dns.reversename.from_address(ip)
            queryresult = my_resolver.query(reversename, 'PTR')[0]
            print '[+] IP: {0: <{1}}  Hostname: {2: <30}'.format(
                ip, MAX_IP_LEN, queryresult)

        except dns.resolver.NXDOMAIN:
            print '[-] IP: {0: <{1}}  No Record Found (NXDOMAIN)'.format(
                ip, MAX_IP_LEN)

        except dns.resolver.Timeout:
            print 'Timed out while resolving {0}'.format(ip)


def dns_lookup(name, longest=40):

    try:
        queryresult = my_resolver.query(name)
        print '[+] IP: {0: <{1}}  Hostname: {2}'.format(
            queryresult.rrset.to_text().split()[-1], MAX_IP_LEN, name)
    except:
        pass



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Perform DNS Queries.")
    parser.add_argument('-r', '--reverse', action='store_true', default=False)
    parser.add_argument('host', metavar='HOST', action='store', help='Hostname or IP Address/IP Subnet')


    args = parser.parse_args()

    if args.reverse:
        try:
            subnet = ipaddress.ip_network(args.host, strict=False)
            dns_reverse_lookup(subnet)
        except:
            print 'Invalid IP Address/Subnet [{0}]'.format(args.host)
    else:
        try:
            subnet = ipaddress.ip_network(args.host, strict=False)
            dns_reverse_lookup(subnet)
        except:
            dns_lookup(args.host)