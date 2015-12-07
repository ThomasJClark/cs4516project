package main

import (
	"log"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
    "github.com/google/gopacket/layers"
)

func processPackets() {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range nfq.GetPackets() {

        if ! isEvil(&packet) && isSiff(&packet) {
            var ipLayer *layers.IPv4
            /*Get the IPv4 layer, or ignore it if it doesn't exist. */
            if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
                value := ipLayer.SrcIP.String() + ipLayer.DstIP.String()
            }
        } else {
		    packet.SetVerdict(netfilter.NF_ACCEPT)
        }
	}
}
