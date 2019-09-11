# Openvpn Forwarder
Forward Openvpn traffic to Mysterium Network nodes

## Quickstart

Build and tun the service via `make build run`

## Install
```
iptables -t nat -A PREROUTING -p tcp -m tcp  --dport 80 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8081
```

## License

This project is licensed under the terms of the GNU General Public License v3.0 (see [details](./LICENSE)).