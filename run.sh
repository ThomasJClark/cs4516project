#!/bin/sh

echo "=============================== BUILDING IMAGES ================================"
docker build -t siff-dr-client ./siff-dr-client/
docker build -t siff-dr-server ./siff-dr-server/

# Start the SIFF-DR-enabled server in the background and the SIFF-DR-enabled
# client in the foreground
echo
echo "============================= STARTING CONTAINERS =============================="
docker run --name server -p 8080:8080 -d siff-dr-server
docker run --name client --rm --link server siff-dr-client

# When the client finishes running, stop all other contianers
echo
echo "================================= CLEANING UP =================================="
docker rm -f $(docker ps -a -q)
