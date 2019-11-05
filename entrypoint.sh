#!/bin/sh
if [ ! -z "$OPENVPN_SUBNET" ] && [ ! -z "$OPENVPN_SERVER" ]; then
    route add -net $OPENVPN_SUBNET gw $OPENVPN_SERVER
fi

exec /forwarder $@
