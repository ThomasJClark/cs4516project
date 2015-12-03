#!/bin/sh

export NET="10.45.16.0/24"

export SERVER="10.45.16.1"
export SERVER_ROUTER="10.45.16.2"
export SIFF_ROUTER1="10.45.16.3"
export SIFF_ROUTER2="10.45.16.4"
export LEGACY_ROUTER="10.45.16.5"
export CLIENT_ROUTER="10.45.16.6"
export CLIENT="10.45.16.7"

export HOSTS="$SERVER        server
              $SERVER_ROUTER server-router
              $SIFF_ROUTER1  siff-router1
              $SIFF_ROUTER2  siff-router2
              $LEGACY_ROUTER legacy-router
              $CLIENT_ROUTER client-router
              $CLIENT        client"

# Add a route for the host to talk to the Docker containers
sysctl net.ipv4.ip_forward=1

echo "=============================== BUILDING IMAGES ================================"
docker build -t siff-dr-client ./siff-dr-client/
docker build -t siff-dr-server ./siff-dr-server/
docker build -t legacy-router ./legacy-router/
docker build -t siff-dr-router1 ./siff-dr-router/
docker build -t siff-dr-router2 ./siff-dr-router/
docker build -t siff-dr-client-router ./siff-dr-client-router/
docker build -t siff-dr-server-router ./siff-dr-server-router/

# Start the containers.  Static IP addresses are set by adding "ip addr ..." to
# the command that Docker runs, since Docker doesn't seem to just have an option
# to specify static IP addressess.
echo
echo "============================= STARTING CONTAINERS =============================="
echo ""
echo "Server"
echo ""
docker run --name server --cap-add=NET_ADMIN -d siff-dr-server /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr add $SERVER dev eth0
    route del -net $NET
    route add -host server-router/32 eth0
    route add default gw server-router
    route add -host client/32 gw server-router
    route
    /go/bin/app"

echo ""
echo "Server router"
echo ""
docker run --name server-router --cap-add=NET_ADMIN --rm siff-dr-server-router /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr add $SERVER_ROUTER dev eth0
    route del -net $NET
    route add -host server/32 eth0
    route add -host siff-router1/32 eth0
    route add -host legacy-router/32 eth0
    route add -host client/32 gw siff-router1
    route add -host siff-router2/32 gw siff-router2
    route add -host client-router/32 gw siff-router1
    route
    #iptables -P FORWARD DROP"

echo ""
echo "Legacy router"
echo ""
docker run --name legacy-router --cap-add=NET_ADMIN -d legacy-router /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr add $LEGACY_ROUTER dev eth0
    route del -net $NET
    route add -host server-router/32 eth0
    route add -host client-router/32 eth0
    route add -host server gw server-router
    route add -host client/32 gw client-router
    route add -host siff-router1/32 gw server-router
    route add -host siff-router2/32 gw client-router
    #iptables -P FORWARD DROP
    sleep 1"

echo ""
echo "SIFF router 1"
echo ""
docker run --name siff-router1 --cap-add=NET_ADMIN --rm siff-dr-router1 /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr add $SIFF_ROUTER1 dev eth0
    route del -net $NET
    route del default
    route add -host server-router/32 eth0
    route add -host siff-router2/32 eth0
    route add -host server gw server-router
    route add -host client gw siff-router2
    route add -host client-router gw siff-router2
    route add -host legacy-router gw server-router
    route
    sleep 1"

echo ""
echo "SIFF router 2"
echo ""
docker run --name siff-router2 --cap-add=NET_ADMIN --rm siff-dr-router2 /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr add $SIFF_ROUTER2 dev eth0
    route del -net $NET
    route add -host client-router/32 eth0
    route add -host siff-router1/32 eth0
    route add -host legacy-router gw client-router
    route add -host client gw client-router
    route add -host server gw siff-router1
    route add -host server-router gw siff-router1
    route
    sleep 1"

echo ""
echo "Client router"
echo ""
docker run --name client-router --cap-add=NET_ADMIN --rm siff-dr-client-router /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr add $CLIENT_ROUTER dev eth0
    route del -net $NET
    route add -host client/32 eth0
    route add -host siff-router2/32 eth0
    route add -host legacy-router/32 eth0
    route add -host siff-router1 gw siff-router2
    route add -host server-router gw siff-router2
    route add -host server gw siff-router2
    route
    sleep 1"

echo ""
echo "Client"
echo ""
docker run --name client --cap-add=NET_ADMIN --rm siff-dr-client /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr add $CLIENT dev eth0
    route del -net $NET
    route add -host client-router/32 eth0
    route add -host server/32 gw client-router
    route add default gw client-router
    route
    /go/bin/app"

# When the client finishes running, stop all other contianers
echo
echo "================================= CLEANING UP =================================="
docker rm -f $(docker ps -a -q)
