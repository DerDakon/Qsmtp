#!/bin/sh

KEYSIZE=4096

# openssl req -x509 -newkey rsa:${KEYSIZE} -keyout valid${KEYSIZE}.key \
# 	-out valid${KEYSIZE}.crt -days 10000 -nodes \
# 	-subj '/C=DE/ST=Some-State/O=Qsmtp testcases/CN=testcert.example.org'
#
# openssl req -x509 -newkey rsa:${KEYSIZE} -keyout valid${KEYSIZE}_san.key \
# 	-out valid${KEYSIZE}_san.crt -days 10000 -nodes \
# 	-subj '/C=DE/ST=Some-State/O=Qsmtp testcases' -addext 'subjectAltName = DNS:testcert.example.org'
#
# openssl req -x509 -newkey rsa:${KEYSIZE} -keyout wildcard${KEYSIZE}.key \
# 	-out wildcard${KEYSIZE}.crt -days 10000 -nodes \
# 	-subj '/C=DE/ST=Some-State/O=Qsmtp testcases/CN=*.example.org'
#
# openssl req -x509 -newkey rsa:${KEYSIZE} -keyout expired.key \
# 	-out expired.crt -days 1 -nodes \
# 	-subj '/C=DE/ST=Some-State/O=Qsmtp testcases/CN=testcert.example.org'

openssl req -x509 -newkey rsa:${KEYSIZE} -keyout valid${KEYSIZE}_san2.key \
	-out valid${KEYSIZE}_san2.crt -days 10000 -nodes \
	-subj '/C=DE/ST=Some-State/O=Qsmtp testcases' \
	-addext 'subjectAltName = DNS:other.example.org, DNS:testcert.example.org'

openssl req -x509 -newkey rsa:${KEYSIZE} -keyout valid${KEYSIZE}_san_cn.key \
	-out valid${KEYSIZE}_san_cn.crt -days 10000 -nodes \
	-subj '/C=DE/ST=Some-State/O=Qsmtp testcases/CN=testcert.example.org' \
	-addext 'subjectAltName = DNS:other.example.org'

openssl req -x509 -newkey rsa:${KEYSIZE} -keyout noname.key \
	-out noname.crt -days 10000 -nodes \
	-subj '/C=DE/ST=Some-State/O=Qsmtp testcases'
