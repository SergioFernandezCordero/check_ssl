#!/usr/bin/python

'''
    check_ssl.py - Check expiration of SSL certificates for your webs
    Sergio Fernandez Cordero <sergio@fernandezcordero.net>
    Python3 refactor and improvements to work seen at http://superuser.com/a/620192
'''

import sys
from OpenSSL import SSL, crypto
import socket
import datetime

from config import config

# On debian Based systems requires python-openssl


def check_config():
    error = 0  # I trust you
    if not isinstance(config.get('host'), str):
        print("ERROR: Host is not a string. Check config")
        error = 1
    if not isinstance(config.get('port'), int) and config.get('port') > 65536:
        print("ERROR: Not a valid port")
        error = 1
    if not isinstance(config.get('method'), str):
        print("ERROR: Not a valid method")
        error = 1
    if config.get('method') != "TLSv1":
        print("WARNING: Methods prior to TLSv1 are not secure.")
        error = 1
    if not isinstance(config.get('critical'), int):
        print("ERROR: Not a valid number of days for critical value")
        error = 1
    if not isinstance(config.get('warning'), int):
        print("ERROR: Not a valid number of days for warning value")
        error = 1
    if not isinstance(config.get('cn'), str):
        print("ERROR: CN is not a string. Check config")
        error = 1
    if error == 1:
        return 1
    elif error == 0:
        return config


def main():

    check = check_config()
    if check == 1:
        print("Errors ocurred in config. Check and try again")
    else:
        host = config.get('host')
        port = int(config.get('port'))
        method = config.get('method')
        critical = int(config.get('critical'))
        warning = int(config.get('warning'))
        cn = config.get('cn')

    # Initialize context
    ctx = SSL.Context(SSL.TLSv1_1_METHOD)

    # Set up client
    try:
        sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.connect((host, port))
    except ConnectionError as e:
        print(e)

    # Send an EOF
    try:
        sock.send("\x04")
        sock.shutdown()
        peer_cert = sock.get_peer_certificate()
        sock.close()
    except SSL.Error as e:
        print(e)

    exit_status = 0
    exit_message = []

    cur_date = datetime.datetime.utcnow()
    cert_nbefore = datetime.datetime.strptime(str(peer_cert.get_notBefore()), 'b\'%Y%m%d%H%M%SZ\'')  # This looks weirdo
    cert_nafter = datetime.datetime.strptime(str(peer_cert.get_notAfter()), 'b\'%Y%m%d%H%M%SZ\'')

    expire_days = int((cert_nafter - cur_date).days)

    if cert_nbefore > cur_date:
        if exit_status < 2:
            exit_status = 2
        exit_message.append('C: cert is not valid')
    elif expire_days < 0:
        if exit_status < 2:
            exit_status = 2
        exit_message.append('Expire critical (expired)')
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

    exit_message.append('['+str(expire_days)+'d]')

    for part in peer_cert.get_subject().get_components():
        if 'b\'CN\'' in str(part[0]):
            cert_cn_pre = str(part[1])[1:]
            cert_cn = cert_cn_pre[1:-1]

    if cn != '' and cn.lower() != cert_cn.lower():
        if exit_status < 2:
            exit_status = 2
        exit_message.append(' - CN mismatch ' + cert_cn + ' in Host ' + host)
    else:
        exit_message.append(' - CN OK in Host ' + host)

        exit_message.append(' - cn:'+ cert_cn)

    print(''.join(exit_message))
    sys.exit(exit_status)

if __name__ == "__main__":
    main()
