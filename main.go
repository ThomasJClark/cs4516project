package main

import (
	"flag"
	"log"

	"github.com/ThomasJClark/cs4516project/siff-dr"
)

func main() {

	modeStr := flag.String("mode", "", "What kind of node in the network to "+
		"act like (client, server, siff-router, legacy-router, or attacker)")

	drop := flag.Int("drop", 0, "The percent of packets to drop in legacy mode")

	flag.Parse()

	log.SetFlags(log.Ltime)
	log.Println("STARTING")

	messages := make(chan siffdr.PendingCU, 2)

	switch *modeStr {
	case "client":
		go siffdr.ProcessOutputPackets(messages)
		go siffdr.ProcessInputPackets(messages)
		requestData()

	case "attacker":
		go siffdr.MakePacketsEvil()
		requestData()

	case "server":
		go siffdr.ProcessOutputPackets(messages)
		go siffdr.ProcessInputPackets(messages)
		serveData()

	case "siff-router":
		siffdr.ProcessForwardPackets()

	case "legacy-router":
		siffdr.DropPackets(*drop)

	default:
		flag.Usage()
	}
}
