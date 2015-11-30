#!/bin/sh

# See addresses.go
export NET="10.45.16.0/24"
export SERVER="10.45.16.1"
export SERVER_ROUTER="10.45.16.2"
export SIFF_ROUTER1="10.45.16.3"
export SIFF_ROUTER2="10.45.16.4"
export LEGACY_ROUTER="10.45.16.5"
export CLIENT_ROUTER="10.45.16.6"
export CLIENT="10.45.16.7"

# Add a route for the host to talk to the Docker containers
sysctl net.ipv4.ip_forward=1

echo "=============================== BUILDING IMAGES ================================"
docker build -t siff-dr-client ./siff-dr-client/
docker build -t siff-dr-server ./siff-dr-server/
docker build -t legacy-router ./legacy-router/

# Start the containers.  Static IP addresses are set by adding "ip addr ..." to
# the command that Docker runs, since Docker doesn't seem to just have an option
# to specify static IP addressess.
echo
echo "============================= STARTING CONTAINERS =============================="
docker run --name server --cap-add=NET_ADMIN -d siff-dr-server /bin/bash -c "
    ip addr add $SERVER dev eth0
    route add -host $LEGACY_ROUTER/32 eth0
    route del -net $NET
    route add -net $NET gw $LEGACY_ROUTER
    /go/bin/app"

docker run --name legacy-router --cap-add=NET_ADMIN -d legacy-router /bin/bash -c "
    ip addr add $LEGACY_ROUTER dev eth0
    route add -net $NET eth0
    sleep 100"

docker run --name client --cap-add=NET_ADMIN --rm siff-dr-client /bin/bash -c "
    ip addr add $CLIENT dev eth0
    route add -host $LEGACY_ROUTER/32 eth0
    route del -net $NET
    route add -net $NET gw $LEGACY_ROUTER
    /go/bin/app"

# When the client finishes running, stop all other contianers
echo
echo "================================= CLEANING UP =================================="
docker rm -f $(docker ps -a -q)
