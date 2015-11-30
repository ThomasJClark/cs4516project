#!/bin/sh

# Add a route for the host to talk to the Docker containers
route add -net 10.45.16.0/24 docker0

echo "=============================== BUILDING IMAGES ================================"
docker build -t siff-dr-client ./siff-dr-client/
docker build -t siff-dr-server ./siff-dr-server/

# Start the containers.  Static IP addresses are set by adding "ip addr ..." to
# the command that Docker runs, since Docker doesn't seem to just have an option
# to specify static IP addressess.
echo
echo "============================= STARTING CONTAINERS =============================="
docker run --name server --cap-add=NET_ADMIN -d   siff-dr-server /bin/bash -c "route add -net 10.45.16.0/24 eth0; ip addr add 10.45.16.1 dev eth0; ../../bin/app"
docker run --name client --cap-add=NET_ADMIN --rm siff-dr-client /bin/bash -c "route add -net 10.45.16.0/24 eth0; ip addr add 10.45.16.7 dev eth0; ../../bin/app"

# When the client finishes running, stop all other contianers
echo
echo "================================= CLEANING UP =================================="
docker rm -f $(docker ps -a -q)
route del -net 10.45.16.0/24
