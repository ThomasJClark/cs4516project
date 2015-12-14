#!/bin/bash

#setup virtual machine for a mac environment
if [[ "$OSTYPE" == "darwin"* ]]; then
    eval "$(docker-machine env default)"
fi

set -e

export NET="10.45.16.0/24"

export SERVER="10.45.16.1"
export SERVER_ROUTER="10.45.16.2"
export SIFF_ROUTER1="10.45.16.3"
export SIFF_ROUTER2="10.45.16.4"
export LEGACY_ROUTER="10.45.16.5"
export CLIENT_ROUTER="10.45.16.6"
export CLIENT="10.45.16.7"
export ATTACKER="10.45.16.8"

export HOSTS="$SERVER        server
              $SERVER_ROUTER server-router
              $SIFF_ROUTER1  siff-router1
              $SIFF_ROUTER2  siff-router2
              $LEGACY_ROUTER legacy-router
              $CLIENT_ROUTER client-router
              $CLIENT        client
              $ATTACKER      attacker"

docker build -t siff .

function cleanupDocker() {
    docker rm -f $(docker ps -a -q) || true 2> /dev/null
}

trap cleanupDocker EXIT

echo "Running containers (check *.log files)"

# Start the containers.  Static IP addresses are set by adding "ip addr ..." to
# the command that Docker runs, since Docker doesn't seem to just have an option
# to specify static IP addressess.
docker run --name server -h server --cap-add=NET_ADMIN -t siff /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr flush dev eth0
    ip addr add $SERVER dev eth0
    route add -host server-router/32 eth0
    route add default gw server-router
    route add -host client/32 gw server-router
    iptables -A OUTPUT -j NFQUEUE --queue-num 0
    iptables -A INPUT -j NFQUEUE --queue-num 1
    /go/bin/cs4516project -mode server" >> server.log 2>&1 &

docker run --name server-router -h server-router --cap-add=NET_ADMIN -t siff /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr flush dev eth0
    ip addr add $SERVER_ROUTER dev eth0
    route add -host server/32 eth0
    route add -host siff-router1/32 eth0
    route add -host legacy-router/32 eth0
    route add -host client/32 gw siff-router1
    iptables -A FORWARD -j NFQUEUE --queue-num 0
    /go/bin/cs4516project -mode siff-router" >> server-router.log 2>&1 &

docker run --name legacy-router -h legacy-router --cap-add=NET_ADMIN -t siff /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr flush dev eth0
    ip addr add $LEGACY_ROUTER dev eth0
    route add -host server-router/32 eth0
    route add -host client-router/32 eth0
    route add -host server gw server-router
    route add -host client/32 gw client-router
    iptables -A FORWARD -j NFQUEUE --queue-num 0
    /go/bin/cs4516project -mode legacy-router -drop 50" >> legacy-router.log 2>&1 &

docker run --name siff-router1 -h siff-router1 --cap-add=NET_ADMIN -t siff /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr flush dev eth0
    ip addr add $SIFF_ROUTER1 dev eth0
    route del default
    route add -host server-router/32 eth0
    route add -host siff-router2/32 eth0
    route add -host server gw server-router
    route add -host client gw siff-router2
    iptables -A FORWARD -j NFQUEUE --queue-num 0
    /go/bin/cs4516project -mode siff-router" >> siff-router1.log 2>&1 &

docker run --name siff-router2 -h siff-router2 --cap-add=NET_ADMIN -t siff /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr flush dev eth0
    ip addr add $SIFF_ROUTER2 dev eth0
    route add -host client-router/32 eth0
    route add -host siff-router1/32 eth0
    route add -host legacy-router gw client-router
    route add -host client gw client-router
    route add -host server gw siff-router1
    iptables -A FORWARD -j NFQUEUE --queue-num 0
    /go/bin/cs4516project -mode siff-router" >> siff-router2.log 2>&1 &

docker run --name client-router -h client-router --cap-add=NET_ADMIN -t siff /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr flush dev eth0
    ip addr add $CLIENT_ROUTER dev eth0
    route add -host client/32 eth0
    route add -host siff-router2/32 eth0
    route add -host legacy-router/32 eth0
    route add -host server gw siff-router2 #legacy-router
    iptables -A FORWARD -j NFQUEUE --queue-num 0
    /go/bin/cs4516project -mode siff-router" >> client-router.log 2>&1 &

docker run --name client -h client --cap-add=NET_ADMIN -t siff /bin/bash -c "
    echo -e '$HOSTS' > /etc/hosts
    ip addr flush dev eth0
    ip addr add $CLIENT dev eth0
    route add -host client-router/32 eth0
    route add -host server/32 gw client-router
    route add default gw client-router
    iptables -A OUTPUT -j NFQUEUE --queue-num 0
    iptables -A INPUT -j NFQUEUE --queue-num 1
    /go/bin/cs4516project -mode client" >> client.log 2>&1

#docker run --name attacker -h attacker --cap-add=NET_ADMIN -t siff /bin/bash -c "
    #echo -e '$HOSTS' > /etc/hosts
    #ip addr flush dev eth0
    #ip addr add $ATTACKER dev eth0
    #route add -host legacy-router/32 eth0
    #route add -host server/32 gw legacy-router
    #route add default gw legacy-router
    #iptables -A OUTPUT -j NFQUEUE --queue-num 0
    #/go/bin/cs4516project -mode attacker" >> attacker.log 2>&1

docker ps -a
