package siffdr

import (
	"log"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*MakePacketsEvil puts the "evil" bit in any outgoing packets.  This is
used by the attacker as a courtesy to inform victims of attacks.*/
func MakePacketsEvil() {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range nfq.GetPackets() {
		EveryVillian(&packet.Packet)

		log.Println("Made packet evil")
		log.Println("Packet flags: ", packet.Packet.NetworkLayer().(*layers.IPv4).Flags)

		data, err := serialize(packet.Packet.NetworkLayer().(*layers.IPv4))
		if err != nil {
			log.Fatal(err)
		}

		packet.SetResult(netfilter.NF_ACCEPT, data)
	}
}

/*EveryVillian makes a packet EVIL*/
func EveryVillian(packet *gopacket.Packet) {
	ipLayer := (*packet).NetworkLayer().(*layers.IPv4)
	ipLayer.Flags |= layers.IPv4EvilBit
}

/*IsLemons returns true if every villian is lemons*/
func IsLemons(packet *gopacket.Packet) bool {
	ipLayer := (*packet).NetworkLayer().(*layers.IPv4)
	return ipLayer.Flags&layers.IPv4EvilBit != 0
}
