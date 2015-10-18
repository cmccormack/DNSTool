import dns.resolver
import dns.reversename
import ipaddress
import argparse

# Used for Debug
DEBUG = True

BAD_DNS = ['68.105.28.12']
OPEN_DNS = ['208.67.222.222', '208.67.220.220']
GOOGLE_DNS = ['8.8.8.8', '8.8.4.4']

DEFAULT_RESOLVER = dns.resolver.Resolver(configure=True)


# Max length of four dot-separated octets (e.g. 255.255.255.255)
MAX_IP_LEN = 15

IN_ADDR = '.in-addr.arpa.'


def debug_print(text, arguments):
    if DEBUG:
        print '[D] {}'.format(text).format(*arguments)


def parse_args():

    parser = argparse.ArgumentParser(description="Perform DNS Queries.")
    parser.add_argument(
        '-r', '--reverse', action='store_true', default=False,
        help='Perform a reverse lookup on an IP address.  \
        This is the default behavior when an IP address is provided.')
    parser.add_argument(
        'host', metavar='HOST', action='store', nargs='?',
        help='Hostname or IP Address/IP Subnet', default='')
    parser.add_argument(
        '-n', '--nameserver', 
        help='Specify Name Server IP or name\
        (e.g. 8.8.8.8 or google-public-dns-a.google.com.)')
    parser.add_argument(
        '-t', '--type', default='A',
        help='Record Type (A, CNAME, NS, ...)')
    parser.add_argument(
        '-f', '--filename',
        help='Specify a file containing a list of IPs or hosts.')
    parser.add_argument(
        '-s', '--subnet', action='store_true', default=False,
        help='Lookup all hosts in subnet.  Defaults to host IP, \
        ignoring prefix.')

    return parser.parse_args()


def print_response(ip, name, type, error_msg='', error_type=''):
    response = 'IP: {0: <{1}}  Hostname: {2:<30}'.format(
        ip, MAX_IP_LEN, name)

    if error_msg:
        response = '[-] {0}[{1} ({2})]'.format(
                response, error_msg, error_type)
    else:
        response = '[+] {}'.format(response)

    print response


def get_host_type(query, query_type='A'):
    '''
        Determine the type of host provided by user.  Object will default to
            dns.name.Name as last resort.

        Parameter(s):
            host - the single host argument provided by the user

        Returns:
            IPv4Address, IPv4Network, or dns.name.Name object
    '''

    # Change query type to reverse lookup if IP address or subnet provided
    try:
        return ipaddress.ip_address(query), 'PTR'
    except ValueError:
        debug_print('get_host_type: {} not an IPv4Address.', query)

    try:
        return ipaddress.ip_network(query), 'PTR'
    except ValueError:
        debug_print('get_host_type: {} not an IPv4Network.', query)

    # Sanity check - must be IP Address to use reversename PTR type
    if query_type is 'PTR':
        query_type = 'A'

    debug_print('get_host_type: {} defaulted to Name type.', query)
    return dns.name.from_text(query), query_type


def dns_lookup(query, query_type='A', resolver=DEFAULT_RESOLVER):

    # Convert IP to reverse-map domain name
    if query_type is 'PTR':
        query = dns.reversename.from_address(query.exploded)

    response = resolver.query(query, query_type)
    return [answer for answer in response]


def dnslookup(hostname='', query_type='A', nameserver='', subnet=False,
              filename='', timeout=2, lifetime=2):

    queries = []
    query_type = query_type.upper()

    # Create new Resolver instance and use System Configuration by default
    my_resolver = dns.resolver.Resolver(configure=True)
    my_resolver.timeout, my_resolver.lifetime = timeout, lifetime

    # Sanitize input host
    if hostname:
        host, host_type = get_host_type(hostname, query_type)

        if isinstance(host, ipaddress.IPv4Network):
            if subnet:
                queries += [(ip, 'PTR') for ip in host]
            else:
                queries.append(get_host_type(hostname.partition('/')[0]))
        else:
            queries.append((host, host_type))

        debug_print('args.host: {} args.type: {}', (host, host_type))

    # Parse nameserver argument to determine if valid
    if nameserver:

        supplied_nameserver = get_host_type(nameserver)[0]
        debug_print('nameserver type: {}', type(supplied_nameserver))
        if isinstance(supplied_nameserver, ipaddress.IPv4Address):
            my_resolver.nameservers = [supplied_nameserver.exploded]

        if isinstance(supplied_nameserver, dns.name.Name):
            try:
                my_resolver.nameservers = map(str, dns_lookup(supplied_nameserver))
            except dns.resolver.NoAnswer:
                print '[x] Cannot resolve nameserver to IP address, ' \
                 'exiting...  [{}]'.format(supplied_nameserver)
                quit()

        # Test if nameserver is valid using nameserver as query
        reversename = dns.reversename.from_address(
            my_resolver.nameservers[0])
        try:
            dns_lookup(reversename, 'PTR')
        except dns.resolver.Timeout:
            print '[x] Connection timed out; no servers could be reached' \
             '  [{}]'.format(supplied_nameserver)
            quit()

        debug_print('nameserver: {}', my_resolver.nameservers[0])

    # Parse file if -f flag set
    if filename:
        with open(filename, 'r') as in_file:
            for line in in_file:
                query = get_host_type(line.strip())

                if isinstance(query, ipaddress.IPv4Network):
                    queries.append((query, 'PTR'))
                else:
                    queries.append((query, query_type))

        print queries

    if queries:
        debug_print('Entering query lookup loop... ', '')
        for items in queries:
            query, query_type = items
            debug_print('\tquery: {} query type: {} record type: {}', (
                query, type(query), query_type))

            try:
                response = dns_lookup(query, query_type)
            except dns.resolver.NXDOMAIN:
                print 'NXDOMAIN [{}]'.format(query)
            for item in response:
                print item
            debug_print('\tdns_lookup.response: {}', (response))

    return response

if __name__ == '__main__':

    args = parse_args()

    response = dnslookup(
        hostname=args.host,
        query_type=args.type,
        nameserver=args.nameserver,
        subnet=args.subnet,
        filename=args.filename)


""" To Do List:
        Work more on nameservers, stuff missing
        Determine if reverse flag is still necessary
        Fix -f flag for ipv4networks
        Breakout functions into private helper functions

"""
