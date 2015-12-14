package siffdr

import (
	"fmt"
	"log"
	"net"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

type PendingCU struct {
	cu  []byte
	ip  net.IP
	exp bool
}

type Capability []byte

/*ProcessOutputPackets intercepts packets before leaving an end host to process
them for siff-dr*/
func ProcessOutputPackets(updates chan PendingCU, capability chan Capability) {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	pending := make(map[string]PendingCU)

	log.Println("Waiting for output packets")
	caps := Capability([]byte{0, 0, 0, 0})
	for packet := range nfq.GetPackets() {
		log.Println("Got packet")
		log.Println("Adding SIFF headers")

		// Empty arrays since don't know capability yet
		var cu []byte
		setExp := false

		tcpLayer := packet.Packet.TransportLayer().(*layers.TCP)
		if tcpLayer.SYN && !tcpLayer.ACK {
			log.Println("Got TCP SYN (not ACK)")
			setExp = true
		}

		var flags uint8
		flags |= IsSiff

		//Put in capability update if one is waiting
		select {
		case update := <-updates:
			pending[update.ip.String()] = update
			log.Println("Got CU, Preparing to send", update.cu)
		default:
			log.Println("No CU, nothing to see here")
		}

		ipLayer := packet.Packet.NetworkLayer().(*layers.IPv4)
		update, updateFound := pending[ipLayer.DstIP.String()]
		if updateFound && update.exp {
			cu = update.cu
			setExp = update.exp
			flags |= CapabilityUpdate
			log.Println("Sending CU to ", ipLayer.DstIP)
		}

		if updateFound {
			delete(pending, ipLayer.DstIP.String())
		}

		if setExp {
			flags |= Exp
		}

		select {
		case caps = <-capability:
			log.Println("Got new capabilities", caps)
		default:
		}

		if isExp(&packet) {
			log.Println("Packet is EXP")
		}
		if isSiff(&packet) {
			log.Println("Packet is SIFF")
		}

		//Make the packet siff
		setSiffFields(&packet, flags, caps, cu)

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

		if hasCapabilityUpdate(&packet) {
			log.Println("Got CU, forwarding")
			addCapability(&packet, calcCapability(&packet))
		} else if isExp(&packet) {
			log.Println("Got exp packet")
			capability := calcCapability(&packet)
			addCapability(&packet, capability)
		} else if isSiff(&packet) {
			log.Println("Got SIFF packet for", hostname(ip.DstIP))
			capability := calcCapability(&packet)
			capabilities := getCapabilities(&packet)
			if len(capabilities) < 1 || capabilities[0] != capability {
				log.Println("Capability mismatch: ", fmt.Sprintf("%d %d, dropping", capability, capabilities))
				packet.SetVerdict(netfilter.NF_DROP)
				continue
			} else {
				log.Println("Capability match, forwarding packet")
			}
			shiftCapability(&packet)
		} else {
			log.Println("Got packet for", hostname(ip.DstIP))
			packet.SetVerdict(netfilter.NF_ACCEPT)
			continue
		}

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

/* Processes input packets to accept or reject SIFF handshakes, and handle capability updates
 */
func ProcessInputPackets(updates chan PendingCU, capability chan Capability) {
	nfq, err := netfilter.NewNFQueue(1, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Waiting for input packets")
	for packet := range nfq.GetPackets() {

		log.Println("INPUT - got a packet")
		//Check for capability updates
		if hasCapabilityUpdate(&packet) {
			log.Println("INPUT Got capability Update", getUpdates(&packet))
			capability <- getUpdates(&packet)
		}
		//Handle EXP packet
		if isSiff(&packet) && isExp(&packet) {
			log.Println("INPUT - Recvd pkt is EXP SIFF")
			capabilities := getCapabilities(&packet)
			//Reverse capabilities
			reverseCapability(capabilities)
			ipLayer := packet.Packet.NetworkLayer().(*layers.IPv4)
			update := PendingCU{cu: capabilities, ip: ipLayer.SrcIP, exp: true}

			if (ipLayer.Flags & layers.IPv4EvilBit) == 0 {
				select {
				case updates <- update:
					fmt.Println("INPUT: queued pending cu")
				default:
					fmt.Println("INPUT: error, pending cu not queued")
				}
			}
		}
		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}
