import dns.resolver
import dns.reversename
import ipaddress
import argparse

# Used for Debug
debug = False

# Create new Resolver instance and use OS resolver by default
my_resolver = dns.resolver.Resolver(configure=True)
my_resolver.timeout = 2
my_resolver.lifetime = 2

# Max length of four dot separated octets (e.g. 255.255.255.255)
MAX_IP_LEN = 15

IN_ADDR = '.in-addr.arpa.'


def dns_lookup(name, query_type='A'):

    if debug: print '[D] dns_lookup: name = {}'.format(name.to_text())
    if debug: print '[D] dns_lookup query_type: {}'.format(query_type)

    name_text = name.to_text()
    short_name = '...{0}'.format(name_text[-27:]) if len(name) > 30 else name_text
    
    try:
        
        response = my_resolver.query(name, query_type).rrset.to_text().split()[-1]

        if debug: print '[D] response: {0}'.format(response)

        if query_type == 'PTR':
            response, name = dns.reversename.to_address(name), response

        print '[+] IP: {0: <{1}}  Hostname: {2:<30}'.format(
            response, MAX_IP_LEN, name)

        return response

    except dns.resolver.NXDOMAIN:
        print '[-] IP: {0: <{1}}  Hostname: {2:<30}  [No Record Found (NXDOMAIN)]'.format(
                '', MAX_IP_LEN, short_name)

    except dns.resolver.NoAnswer:
        print '[-] IP: {0: <{1}}  Hostname: {2:<30}  [No Record Found (NoAnswer)]'.format(
                '', MAX_IP_LEN, short_name)

    except dns.resolver.Timeout:
        print 'Timed out while resolving {0}'.format(name)




if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Perform DNS Queries.")
    parser.add_argument('-r', '--reverse', action='store_true', default=False,
        help='Perform a reverse lookup on an IP address.  \
        This is the default behavior when an IP address is provided')
    parser.add_argument('host', metavar='HOST', action='store', 
        help='Hostname or IP Address/IP Subnet')
    parser.add_argument('-ns', '--nameserver', nargs='?',
        help='Specify Name Server \
        (e.g. 8.8.8.8 or google-public-dns-a.google.com.)')
    parser.add_argument('-t', '--type', default='A',
        help='Record Type (A, CNAME, NS, ...)')

    args = parser.parse_args()
    args.type = args.type.upper()

    if args.nameserver:
        try:
            nameserver = ipaddress.ip_address(args.nameserver).exploded
        except:
            nameserver = dns_lookup(args.nameserver)

        my_resolver = dns.resolver.Resolver(configure=False)
        my_resolver.nameservers = [nameserver]
        my_resolver.timeout = 2
        my_resolver.lifetime = 2


    if debug: print '[D] args.reverse: {}'.format(args.reverse)
    if debug: print '[D] args.host: {}'.format(args.host)
    if debug: print '[D] args.type: {}'.format(args.type)
    if debug: print '[D] Nameservers: {}'.format(my_resolver.nameservers)


    # Check if HOST is IP Address/Subnet.  Ignores invalid type flag
    try:
        query = ipaddress.ip_network(args.host, strict=False)
        args.type = 'PTR'
    except ValueError:
        query = dns.name.from_text(args.host)
    if debug: print '[D] query: {} type: {}'.format(query, type(query))

    if args.type == 'PTR':
        for ip in query:
            reversename = dns.reversename.from_address(ip.exploded)
            #if debug: print '[D] reversename = {}'.format(reversename.to_text())
            dns_lookup(reversename, query_type='PTR')

    if args.type.upper() in ['A', 'CNAME', 'DNAME', 'NS', 'MX', 'SOA']:
        dns_lookup(query, args.type)


