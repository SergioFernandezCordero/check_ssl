#!/usr/bin/python

'''
    check_ssl.py - Check expiration of SSL certificates for your webs
    Sergio Fernandez Cordero <sergio@fernandezcordero.net>
'''

import sys
import ssl
import socket
from datetime import datetime

from config import config


def check_config():
    error = 0  # I trust you
    if ssl.HAS_SNI is not True:  # Show alert if SNI not supported
        print("WARNING: Your Python installation doens't support SNI.\nThis will cause tests on Virtualhosts fail!")
    if not isinstance(config.get('host'), str):
        print("ERROR: Host is not a string. Check config")
        error = 1
    if not isinstance(config.get('port'), int) and config.get('port') > 65536:
        print("ERROR: Not a valid port")
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
        sys.exit(1)
    else:
        host = config.get('host')
        port = int(config.get('port'))
        critical = int(config.get('critical'))
        warning = int(config.get('warning'))
        cn = config.get('cn')

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

    # Let's check valid names!
    for cert_cn in canonicals:
        if cn != '' and cn.lower() != cert_cn.lower():
            if exit_status < 2:
                exit_status = 2
            exit_message.append(' - CN mismatch ' + cert_cn + ' in Host ' + host + "(" + cn + ")")
        else:
            exit_message.append(' - CN OK in Host ' + host + "(" + cn + ")")

    print(''.join(exit_message))
    sys.exit(exit_status)

if __name__ == "__main__":
    main()
