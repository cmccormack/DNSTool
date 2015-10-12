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

# Max length of four dot-separated octets (e.g. 255.255.255.255)
MAX_IP_LEN = 15

IN_ADDR = '.in-addr.arpa.'


def print_response(ip, name, type, error_msg, error_type):
    response = 'IP: {0: <{1}}  Hostname: {2:<30}'.format(
        ip, MAX_IP_LEN, name)

    if error_msg:
        response = '[-] {0}[{1} ({2})]'.format(
                response, error_msg, error_type)
    else:
        response = '[+] {}'.format(response)

    print response

def dns_lookup(query, query_type='A'):

    # Parse name from dns.name.Name object and shorten to fit if gt 30 characters
    query_text = query.to_text()
    short_name = '...{0}'.format(query_text[-27:]) if len(query) > 30 else query_text
    
    try:
        # Query DNS server and parse relevant string from response
        response = my_resolver.query(query, query_type).rrset.to_text().split()[-1]

        # Swap response and name for reverse lookups to fit column scheme
        if query_type == 'PTR':
            response, query = dns.reversename.to_address(query), response

        print '[+] IP: {0: <{1}}  Hostname: {2:<30}'.format(
            response, MAX_IP_LEN, query)

        return response

    except dns.resolver.NXDOMAIN:
        print_response('', query, query_type, 'No Record Found', 'NXDOMAIN')

    except dns.resolver.NoAnswer:
        print_response('', query, query_type, 'No Record Found', 'NoAnswer')

    except dns.resolver.Timeout:
        print_response('', query, query_type, 'Timed Out', 'Timeout')




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


    # Parse nameserver argument to determine if valid 
    nameserver = None
    if args.nameserver:
        print args.nameserver
        # Check if provided nameserver is IP Address or Name
        try:
            nameserver = ipaddress.ip_address(args.nameserver).exploded

        except:
            nameserver = dns_lookup(dns.name.from_text(args.nameserver))

        if nameserver:
            my_resolver = dns.resolver.Resolver(configure=False)
            my_resolver.nameservers = [nameserver]
            my_resolver.timeout = 2
            my_resolver.lifetime = 2
        else:
            print '[-] {0} is not a valid nameserver, exiting...'.format(args.nameserver)
            quit()

            


    # Check if HOST is IP Address/Subnet.  Ignores invalid type flag
    try:
        query = ipaddress.ip_network(args.host, strict=False)
        args.type = 'PTR'
    except ValueError:
        query = dns.name.from_text(args.host)

    if args.type == 'PTR':
        for ip in query:
            reversename = dns.reversename.from_address(ip.exploded)
            dns_lookup(reversename, query_type='PTR')

    if args.type.upper() in ['A', 'CNAME', 'DNAME', 'NS', 'MX', 'SOA']:
        dns_lookup(query, args.type)


