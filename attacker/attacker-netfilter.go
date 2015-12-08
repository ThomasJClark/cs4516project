package main

import (
	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
	"log"
)

func processPackets() {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range nfq.GetPackets() {
		everyVillainIsLemons(&packet)
		if isEvil(&packet) {
			log.Println("Am packet. Can confirm am evil")
		} else {
			log.Println("Am packet. Can confirm am not evil")
		}
		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}
