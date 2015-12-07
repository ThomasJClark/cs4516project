package main

import (
	"log"
	"math/rand"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
)

/*
start netfilter queue and process packets, droping drop percent of them
*/
func processPackets(drop int) {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range nfq.GetPackets() {
		dropP := rand.Intn(100)
		if dropP < drop {
			packet.SetVerdict(netfilter.NF_DROP)
		} else {
			packet.SetVerdict(netfilter.NF_ACCEPT)
		}

	}
}
