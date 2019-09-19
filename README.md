# Openvpn Forwarder
Forward Openvpn traffic to Mysterium Network nodes



## Quickstart

Build and run the service via `make build run`



## Redirect Openvpn's traffic (from host machine)
Lets assume:
- You are SSH'ed to server
- You run Openvpn server on host machine here

1. Run forwarder as Docker container:
```bash
docker run -d --name forwarder -p 127.0.0.1:8080:8080 -p 127.0.0.1:8443:8443 mysteriumnetwork/openvpn-forwarder \
    --proxy.upstream-url="http://superproxy.com:8080" \
    --filter.hostnames="ipinfo.io"
```

2. Redirect HTTP ports to forwarder:
```bash
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 172.18.0.4:8080
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 443 -j DNAT --to-destination 172.18.0.4:8443
```

3. Forwarder redirects HTTP traffic to upstream HTTPS proxy (this case just hostname 'ipinfo.io'):
```bash
sudo openvpn --config client.ovpn
curl "http://ipinfo.io/"
curl "https://ipinfo.io/"
```



## Redirect Openvpn's traffic (from Docker container)
Lets assume:
- You are SSH'ed to server
- You run Openvpn server inside Docker container named 'openvpn'
- Your Openvpn container is assigned to Docker network 'openvpn_network'

1. Run forwarder as Docker container:
```bash
docker run -d --name forwarder --net openvpn_network mysteriumnetwork/openvpn-forwarder \
    --proxy.upstream-url="http://superproxy.com:8080" \
    --filter.hostnames="ipinfo.io,whatismyipaddress.com"
```

2. Find what IP forwarder was assigned:
```bash
FORWARDER_IP=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' forwarder`
```

3. Redirect HTTP ports to forwarder (from Docker container):
```bash
docker exec -it colibri iptables -A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination $FORWARDER_IP:8080
docker exec -it colibri iptables -A PREROUTING -p tcp -m tcp --dport 443 -j DNAT --to-destination $FORWARDER_IP:8443
```

3. Forwarder redirects HTTP traffic to upstream HTTPS proxy (this case just 2 hostnames):
```bash
sudo openvpn --config client.ovpn
curl "http://ipinfo.io/"
curl "https://ipinfo.io/"
```



## License

This project is licensed under the terms of the GNU General Public License v3.0 (see [details](./LICENSE)).