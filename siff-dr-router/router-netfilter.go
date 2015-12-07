package main

import (
	"log"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
)

func processPackets() {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range nfq.GetPackets() {

        if ! isEvil(&packet) && isSiff(&packet) {
            capability := getCapability(&packet)
		    packet.SetVerdict(netfilter.NF_ACCEPT)
        } else {
		    packet.SetVerdict(netfilter.NF_ACCEPT)
        }
	}
}
