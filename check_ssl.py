#!/usr/bin/python

'''
    check_ssl.py - Check expiration of SSL certificates for your services
    Sergio Fernandez Cordero <sergio@fernandezcordero.net>
'''

import sys
import ssl
import socket
import argparse
from datetime import datetime

# Config parameters. Change to your needs. If you wanna use default, delete the corresponding line

# Parse arguments about receiver
parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server", help="FQDN hostname to connect", type=str)
parser.add_argument("-p", "--port", help="Destination port. Defaults to 443", type=int)
parser.add_argument("-c", "--crit", help="Critical threshold. Defaults to 5", type=int)
parser.add_argument("-w", "--warn", help="Warning threshold. Defautls to 15", type=int)
parser.add_argument("-cn", "--canonical", help="Canonical name to check. Defaults to --host", type=str)
try:
    args = parser.parse_args()
except TypeError as e:
    print(e)
    sys.exit(1)

# Check configuration parameters
def check_config():
    if ssl.HAS_SNI is not True:  # Show alert if SNI not supported
        print("WARNING: Your Python installation doens't support SNI.\nThis will cause tests on Virtualhosts fail!")
    if not args.server or not isinstance(args.server, str):
        print("ERROR: Host not set or is not a string. Check config")
        sys.exit(1)
    else:
        host = args.server
    if not args.port or args.port > 65536:
        port = 443
    else:
        port = args.port
    if not args.crit or not isinstance(args.crit, int):
        critical = 5
    else:
        critical = args.crit
    if not args.warn or not isinstance(args.warn, int):
        warning = 15
    else:
        warning = args.warn
    if not args.canonical or not isinstance(args.canonical, str):
        cn = host
    else:
        cn = args.canonical
    return host, port, warning, critical, cn

# Check if configuration introduced is valid or use defaults and extract values
host, port, warning, critical, cn = check_config()

# Initialize context
ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

try:
    sock = socket.socket()
    socks = ctx.wrap_socket(sock, server_hostname=host)
    socks.connect((host, port))
except ConnectionError as e:
    print(e)
try:
    cert = socks.getpeercert(binary_form=False)
except ssl.SSLError as e:
    print(e)

# Fun with dates! Check https://docs.python.org/3/library/ssl.html#ssl.cert_time_to_seconds
cert_notafter = cert['notAfter']
cert_notbefore = cert['notBefore']

exit_status = 0
exit_message = []

cur_date = datetime.utcnow()
cert_nbefore = datetime.strptime(str(cert_notbefore), '%b %d %H:%M:%S %Y %Z')
cert_nafter = datetime.strptime(str(cert_notafter), '%b %d %H:%M:%S %Y %Z')
expire_days = int((cert_nafter - cur_date).days)

# Get commonName and SubjectAltNames for validation
# List of possible names
canonicals = []
# CommonName
subject = cert['subject']
for key in subject:
    for subkey, value in key:
        if subkey == "commonName":
            canonicals.append(value)
# SubjectAltNames
san = cert['subjectAltName']
for common, name in san:
    if name not in canonicals:
        canonicals.append(name)

# Let's check expirations!
if cert_nbefore > cur_date:
    if exit_status < 2:
        exit_status = 2
    exit_message.append('C: cert is not valid')
elif expire_days < 0:
    if exit_status < 2:
        exit_status = 2
    exit_message.append('Expire critical ###EXPIRED###')
elif critical > expire_days:
    if exit_status < 2:
        exit_status = 2
    exit_message.append('Expire critical')
elif warning > expire_days:
    if exit_status < 1:
        exit_status = 1
    exit_message.append('Expire warning')
else:
    exit_message.append('Expire OK')

exit_message.append(' '+str(expire_days)+'d')

# Let's check valid names!
for cert_cn in canonicals:
    if cn != '' and cn.lower() != cert_cn.lower():
        if exit_status < 2:
            exit_status = 2
        exit_message.append(' - CN mismatch ' + cert_cn + ' in Host ' + host + "(" + cn + ")")
    else:
        exit_message.append(' - CN OK in Host ' + host + "(" + cn + ")")

# Get your output
print(''.join(exit_message))
sys.exit(exit_status)

