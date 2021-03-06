package main

import (
	"flag"
	"log"
	"time"

	"github.com/ThomasJClark/cs4516project/siff-dr"
)

func main() {

	modeStr := flag.String("mode", "", "What kind of node in the network to "+
		"act like (client, server, siff-router, legacy-router, or attacker)")

	drop := flag.Int("drop", 0, "The percent of packets to drop in legacy mode")

	flag.Parse()

	log.SetFlags(log.Ltime)
	log.Println("STARTING")

	updates := make(chan siffdr.PendingCU, 2)
	capability := make(chan siffdr.Capability, 2)

	switch *modeStr {
	case "client":
		go siffdr.ProcessOutputPackets(updates, capability)
		go siffdr.ProcessInputPackets(updates, capability)

		time.Sleep(1)
		measureData(100)

	case "attacker":
		go siffdr.MakePacketsEvil()
		time.Sleep(1)
		requestData()

	case "server":
		go siffdr.ProcessOutputPackets(updates, capability)
		go siffdr.ProcessInputPackets(updates, capability)
		serveData()

	case "siff-router":
		go siffdr.DetectAttacks(func() {
			log.Println("Timed Out - UNDER ATTACK!!!!!")
		}, "legacy-router")
		siffdr.ProcessForwardPackets()

	case "legacy-router":
		siffdr.DropPackets(*drop)

	default:
		flag.Usage()
	}
}
