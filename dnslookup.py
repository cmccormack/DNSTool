import dns.resolver
import dns.reversename
import ipaddress
import argparse

my_resolver = dns.resolver.Resolver()

# Use Google and OpenDNS NameServers by default
my_resolver.nameservers = [
    '8.8.8.8', 
    '208.67.222.222', 
    '8.8.4.4', 
    '208.67.220.220'
]

my_resolver.timeout = 1

# Max length of four dot separated octets (e.g. 255.255.255.255)
MAX_IP_LEN = 15

def dns_reverse_lookup(subnet):

    for ip in subnet:
        try:
            ip = ip.exploded
            reversename = dns.reversename.from_address(ip)
            queryresult = my_resolver.query(reversename, 'PTR')[0]
            print '[+] IP: {0: <{1}}  Hostname: {2: <30}'.format(
                ip, MAX_IP_LEN, queryresult)

        except dns.resolver.NXDOMAIN:
            print '[-] IP: {0: <{1}}  [No Record Found (NXDOMAIN)]'.format(
                ip, MAX_IP_LEN)

        except dns.resolver.Timeout:
            print 'Timed out while resolving {0}'.format(ip)
    print 


def dns_lookup(name, longest=40):

    try:
        queryresult = my_resolver.query(name)
        print '[+] IP: {0: <{1}}  Hostname: {2}'.format(
            queryresult.rrset.to_text().split()[-1], MAX_IP_LEN, name)
    except:
        print '[-] IP: {0: <{1}}  Hostname: {2}  [No Record Found (NXDOMAIN)]'.format(
                '', MAX_IP_LEN, name)



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Perform DNS Queries.")
    parser.add_argument('-r', '--reverse', action='store_true', default=False,
        help='Perform a reverse lookup on an IP address.  \
        This is the default behavior when an IP address is provided')
    parser.add_argument('host', metavar='HOST', action='store', 
        help='Hostname or IP Address/IP Subnet')

    args = parser.parse_args()

    if args.reverse:
        try:
            subnet = ipaddress.ip_network(args.host, strict=False)
            dns_reverse_lookup(subnet)
        except:
            print 'Invalid IP Address/Subnet [{0}]\n'.format(args.host)
    else:
        try:
            subnet = ipaddress.ip_network(args.host, strict=False)
            dns_reverse_lookup(subnet)
        except:
            dns_lookup(args.host)






