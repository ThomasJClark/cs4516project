package siffdr

import (
	"log"
	"math/rand"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

/*DropPackets start netfilter queue and process packets, dropping drop percent
of them*/
func DropPackets(drop int) {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Waiting for packets to drop")
	for packet := range nfq.GetPackets() {
		ip := packet.Packet.NetworkLayer().(*layers.IPv4)
		log.Println("Got SIFF packet for", hostname(ip.DstIP))

		if IsLemons(&packet.Packet) {
			log.Println("Packet is EVIL!")
			log.Println("Forwarding anyways because I don't implement RFC 3514")
		}

		dropP := rand.Intn(100)
		if dropP < drop {
			log.Println("Never mind, randomly dropping packet")
			packet.SetVerdict(netfilter.NF_DROP)
		} else {
			packet.SetVerdict(netfilter.NF_ACCEPT)
		}

	}
}
