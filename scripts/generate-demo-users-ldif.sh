#!/bin/sh

set -e

CURL=curl

$CURL -qs https://raw.githubusercontent.com/kopano-dev/kopano-docker/master/ldap_demo/bootstrap/ldif/demo-users.ldif | sed "s;{{ LDAP_DOMAIN }};$(hostname -f);g" | sed "s;{{ LDAP_BASE_DN }};dc=nodomain;g"

