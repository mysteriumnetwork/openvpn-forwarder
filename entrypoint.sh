#!/bin/sh
# example: EXTRA_ROUTES="10.1.1.0/24:10.10.10.1,10.2.2.0/24:10.20.20.1"
IFS=',' read -ra ROUTES <<< "$EXTRA_ROUTES"
for route in "${ROUTES[@]}"; do
    IFS=':' read -a args <<< "$route"
    echo route add -net ${args[0]} gw ${args[1]}
done

exec /forwarder $@
