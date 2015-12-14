package siffdr

import (
	"fmt"
	"log"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

type PendingCU struct {
	cu  []byte
	exp bool
}

/*ProcessOutputPackets intercepts packets before leaving an end host to process
them for siff-dr*/
func ProcessOutputPackets(updates chan PendingCU) {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Waiting for output packets")
	for packet := range nfq.GetPackets() {
		log.Println("Got packet")
		log.Println("Adding SIFF headers")

		// Empty arrays since don't know capability yet
		caps := []byte{7, 8, 9, 10}
		var cu []byte

		//TODO handle sending exp
		select {
		case update := <-updates:
			log.Println("Got CU, Prepareing to send", update.cu)
			cu = update.cu
		default:
			log.Println("No CU, nothing to see here")
		}

		var flags layers.IPv4Flag
		flags |= IS_SIFF
		setSiffFields(&packet, flags, caps, cu)

		if isSiff(&packet) {
			log.Println("Packet is SIFF")
		}

		//packet.SetVerdict(netfilter.NF_ACCEPT)
		// Get serialization of modified packet
		serializedPacket, err := serialize(packet.Packet.NetworkLayer().(*layers.IPv4))
		if err != nil {
			log.Println(err)
			log.Println("Failed to serialize packet, dropping")
			packet.SetVerdict(netfilter.NF_DROP)
		} else {
			packet.SetResult(netfilter.NF_ACCEPT, serializedPacket)
		}
	}
}

/*ProcessForwardPackets intercepts packets before being forwarded on a router to
process them for siff-dr*/
func ProcessForwardPackets() {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Waiting for forward packets")
	for packet := range nfq.GetPackets() {
		ip := packet.Packet.NetworkLayer().(*layers.IPv4)

		if isSiff(&packet) {
			log.Println("Got SIFF packet for", hostname(ip.DstIP))
			capability := calcCapability(&packet)
			if isExp(&packet) {
				addCapability(&packet, capability)
			} else {
				capabilities := getCapabilities(&packet)
				shiftCapability(&packet)
				if len(capabilities) < 1 || capabilities[0] != capability {
					log.Println("Capability mismatch: ", fmt.Sprintf("%c %c, dropping", capability, capabilities))
					packet.SetVerdict(netfilter.NF_DROP)
					continue
				} else {
					log.Println("Capability match, forwarding packet")
				}
			}
			serializedPacket, err := serialize(packet.Packet.NetworkLayer().(*layers.IPv4))
			if err != nil {
				log.Println(err)
				log.Println("Failed to serialize packet, dropping")
				packet.SetVerdict(netfilter.NF_DROP)
			} else {
				packet.SetResult(netfilter.NF_ACCEPT, serializedPacket)
			}
			continue
		} else {
			log.Println("Got packet for", hostname(ip.DstIP))
		}

		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}

/* Processes input packets to accept or reject SIFF handshakes, and handle capability updates
 */
func ProcessInputPackets(updates chan PendingCU) {
	nfq, err := netfilter.NewNFQueue(1, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Waiting for input packets")
	for packet := range nfq.GetPackets() {

		log.Println("INPUT - got a packet")
		if isSiff(&packet) && isExp(&packet) {
			log.Println("INPUT - Recvd pkt is EXP SIFF")
			capabilities := getCapabilities(&packet)
			//Reverse capabilities
			reverseCapability(capabilities)
			update := PendingCU{cu: capabilities, exp: true}

			select {
			case updates <- update:
				fmt.Println("INPUT: sent pending cu")
			default:
				fmt.Println("INPUT: error, pending cu not sent")
			}

		}
		packet.SetVerdict(netfilter.NF_ACCEPT)

	}

}
