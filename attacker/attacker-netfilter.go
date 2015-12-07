package main

import (
	"log"
	"fmt"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
)

func processPackets() {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range nfq.GetPackets() {
		EveryVillainIsLemons(&packet)
		if (isEvil(&packet)) {
			fmt.Printf("Am packet. Can confirm evil")
		} else {
			fmt.Printf("Am packet. Can not confirm evil")
		}
		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}
