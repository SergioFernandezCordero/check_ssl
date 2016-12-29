# check-ssl.py - Check expiration of SSL certificates for your services

**check-ssl.py** can check time for expiration in days of your server certificates.
Also, it can check _commonName_ and _SubjectAltName_ for validation and testing purposes.
It implements [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication), so multiple virtualhosts are supported.

To run, simply copy config.py.example to config.py and tuen following parameters:

* **host**: FWDN which will be invocated
* **port**: Port where TLS connection is listening (f.e. 443)
* **critical:** Days to expiration, set as critical
* **warning:** Days to expiration, set as warning
* **cn:** Canonical name which is expected in certificate. Will be checked
against all commonName and SubjectAltNames present in certs.

### TODO:

- Implement default values
- Let user define TLS/SSL version protocol to use. TLSv1_1 is used now
- Parseable format output, perhaps JSON