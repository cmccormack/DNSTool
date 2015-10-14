import dns.resolver
import dns.reversename
import ipaddress
import argparse

# Used for Debug
debug = True

BAD_DNS = ['68.105.28.12']
OPEN_DNS = ['208.67.222.222', '208.67.220.220']
GOOGLE_DNS = ['8.8.8.8', '8.8.4.4']
PREFERRED_DNS = BAD_DNS
DNS_TIMEOUT = 2
DNS_LIFETIME = 2

 

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



def get_host_type(host):
    try:
        return ipaddress.ip_network(host)

    except ValueError:
        return dns.name.from_text(host)



def dns_lookup(query, query_type='A'):

    response = my_resolver.query(query, query_type)
    return [answer for answer in response]





if __name__ == '__main__':

    # Create new Resolver instance and use System Configuration by default
    my_resolver = dns.resolver.Resolver(configure=True)
    my_resolver.timeout = DNS_TIMEOUT
    my_resolver.lifetime = DNS_LIFETIME 

    # Argparse
    parser = argparse.ArgumentParser(description="Perform DNS Queries.")
    parser.add_argument('-r', '--reverse', action='store_true', default=False,
        help='Perform a reverse lookup on an IP address.  \
        This is the default behavior when an IP address is provided')
    parser.add_argument('host', metavar='HOST', action='store', nargs='?',
        help='Hostname or IP Address/IP Subnet', default='')
    parser.add_argument('-n', '--nameserver', 
        help='Specify Name Server \
        (e.g. 8.8.8.8 or google-public-dns-a.google.com.)')
    parser.add_argument('-t', '--type', default='A',
        help='Record Type (A, CNAME, NS, ...)')
    parser.add_argument('-f', '--filename',
        help='Specify a file containing a list of IPs or hosts.')

    args = parser.parse_args()
    query_type = args.type.upper()
    queries = []


    if args.host:
        host, host_type = get_host_type(args.host), args.type
        if isinstance(host, ipaddress.IPv4Network): host_type = 'PTR'
        queries.append((host, host_type))


    # Parse nameserver argument to determine if valid 
    if args.nameserver:

        # Check if provided nameserver is an IP Address or Name
        nameserver = get_host_type(args.nameserver)
        if isinstance(nameserver, dns.name.Name):
            try:
                nameserver = dns_lookup(nameserver)
            except:
                print 'Cannot resolve nameserver to IP address, ' \
                 'exiting...  [{}]'.format(nameserver)
                quit()

        if debug: print '[D] nameserver: {}'.format(nameserver)
        my_resolver.nameservers = [nameserver]



    # Parse file if -f flag set
    if args.filename:
        with open(args.filename, 'r') as f:
            for line in f:
                query = get_host_type(line.strip())

                if isinstance(query, ipaddress.IPv4Network):
                    queries.append((query, 'PTR'))
                else:
                    queries.append((query, args.type))


    if queries:
        for query in queries:
            response = dns_lookup(*query)
            for item in response:
                print item
            if debug: '[D] dns_lookup.response: {}'.format(response)
        """except:
            print 'Error resolving host, exiting...  [{}]'.format(query)
            quit()"""
