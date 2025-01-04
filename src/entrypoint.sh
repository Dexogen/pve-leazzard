#!/bin/bash
set -e

cat <<EOF > /etc/dnsmasq.conf
domain=${DNS_DOMAIN}
expand-hosts
local=/${DNS_DOMAIN}/
dhcp-range=${DHCP_RANGE}
dhcp-option=${DHCP_OPTION}
conf-dir=/etc/dnsmasq.d/,*.conf
EOF

exec supervisord -c /etc/supervisord.conf