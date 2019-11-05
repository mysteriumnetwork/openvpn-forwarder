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
docker run -d --name forwarder -p 127.0.0.1:8080:8080 -p 127.0.0.1:8443:8443 --cap-add NET_ADMIN mysteriumnetwork/openvpn-forwarder \
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
docker run -d --name forwarder --net openvpn_network --cap-add NET_ADMIN mysteriumnetwork/openvpn-forwarder \
    --proxy.upstream-url="http://superproxy.com:8080" \
    --filter.hostnames="ipinfo.io,whatismyipaddress.com"
```

2. Find what IP forwarder was assigned:
```bash
FORWARDER_IP=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' forwarder`
```

3. Redirect HTTP ports to forwarder (from Docker container):
```bash
docker exec -it openvpn iptables -t nat -A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination $FORWARDER_IP:8080
docker exec -it openvpn iptables -t nat -A PREROUTING -p tcp -m tcp --dport 443 -j DNAT --to-destination $FORWARDER_IP:8443
```

4. Forwarder redirects HTTP traffic to upstream HTTPS proxy (this case just 2 hostnames):
```bash
sudo openvpn --config client.ovpn
curl "http://ipinfo.io/"
curl "https://ipinfo.io/"
```

## User session stickiness

To enable user stickiness the following configuration is required from the OpenVPN server:

Add the following line to the `/etc/openvpn/openvpn.conf` file:

```
learn-address /etc/openvpn/stick-user.sh
```

And create the file `/etc/openvpn/stick-user.sh` file:

```
#!/bin/bash
if [[ "$1" == "add" || "$1" == "update" ]]; then
	userHash=$(echo $3 | sha256sum | cut -d' ' -f1)
	curl -i -X POST http://forwarder:8000/api/v1/map -H "Accept: application/json" -H "Content-Type: application/json" -d "{\"ip\":\"$2\",\"userId\":\"$userHash\"}"
fi
```

```
#!/bin/bash
if [[ "$1" == "add" || "$1" == "update" ]]; then
    userHash=$(echo $3 | sha256sum | cut -d' ' -f1)
    wget -q -O - --header="Accept: application/json" --header="Content-Type: application/json" --post-data="{\"ip\":\"$2\",\"userId\":\"$userHash\"}" http://forwarder:8000/api/v1/map
fi
```

This will send an update to `forwarder` with virtual IP to UserHash mapping on every user connection.

To be able to get user's virtual IP for mapping we need to disable `MASQUERADE` to the `forwarder` container:

Execute the following command on the `openvpn` container:
```
docker exec -it openvpn iptables -t nat -A POSTROUTING ! -d forwarder -j MASQUERADE
```

And the `forwarder` container should be started with the following environment variables:
```
docker run -d --name forwarder --net openvpn_network -e "OPENVPN_SUBNET=192.168.255.0/24" -e "OPENVPN_SERVER=openvpn" \
    --cap-add NET_ADMIN mysteriumnetwork/openvpn-forwarder \
    --proxy.upstream-url="http://superproxy.com:8080" \
    --filter.hostnames="ipinfo.io,whatismyipaddress.com"
```

* `192.168.255.0/24` - is a OpenVPN subnet that will be used for virtual IPs of clients;
* `forwarder` - is a container name of the OpenVPN-forwarder, this name should resolve from any container in the `openvpn_network` docker network.
* `openvpn` - is a container name of the OpenVPN server, this name should resolve from any container in the `openvpn_network` docker network.


## Debugging of traffic
1. Check your server's current IP
```bash
curl "http://ipinfo.io/"
```

2. Check if your upstream HTTPS proxy is accepting requests
```bash
curl --proxytunnel --proxy superproxy.com:8080 "http://ipinfo.io/"
```
You are supposed to see your server's IP changed

3. Check if forwarder is redirecting requests to upstream HTTPS proxy
```bash
FORWARDER_IP=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' forwarder`
curl --proxy $FORWARDER_IP:8080 "http://ipinfo.io"
```
You should see different current IP of your server

4. Check if traffic of Openvpn's container is being forwarded
```bash
docker exec -it openvpn curl "https://ipinfo.io/"
OR
docker exec -it openvpn wget -q -O - "https://ipinfo.io/"
```


## License

This project is licensed under the terms of the GNU General Public License v3.0 (see [details](./LICENSE)).
