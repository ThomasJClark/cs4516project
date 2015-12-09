package main

import (
	"bytes"
	"log"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// This is Tom's black magic ask him
func Serialize(ipLayer *layers.IPv4) ([]byte, error) {
	/*Write the IPv4 header into a gopacket buffer*/
	buf := gopacket.NewSerializeBuffer()
	err := ipLayer.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: true})
	if err != nil {
		return nil, err
	}

	/*Write the gopacket buffer and the payload into a byte buffer, concatenating
	  the entire packet together.*/
	var buf2 bytes.Buffer
	buf2.Write(buf.Bytes())
	buf2.Write(ipLayer.Payload)

	return buf2.Bytes(), nil
}

func processPackets() {
	log.Println("Starting router queue")
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range nfq.GetPackets() {
		log.Println("Got packet")

		// If packet is SIFF
		if isSiff(&packet) {
			// Get capability
			capability := calcCapability(&packet)
			// If packet is exploration, add capability
			if isExp(&packet) {
				log.Println("Got exp packet")
				addCapability(&packet, capability)
			} else {
				// Otherwise check that the lowest capability matches ours
				capabilities := getCapabilities(&packet)
				// If there isn't one or it doesn't match, drop the packet
				if len(capabilities) < 1 || capability != getCapabilities(&packet)[0] {
					log.Println("Capability mismatch")
					packet.SetVerdict(netfilter.NF_DROP)
				}
			}
			// Shift our capability off
			shiftCapability(&packet)

			var ipLayer *layers.IPv4
			/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
			   I can't be arsed for proper response outside the bounds of this project */
			if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
				ipLayer = layer.(*layers.IPv4)
			} else {
				// maybe do something?
			}

			// Serialize packet to pass back to netfilter
			serializedPacket, err := Serialize(ipLayer)
			if err != nil {
				log.Println("Failed to serialize packet, dropping")
				packet.SetVerdict(netfilter.NF_DROP)
			} else {
				packet.SetResult(netfilter.NF_ACCEPT, serializedPacket)
			}
		} else {
			packet.SetVerdict(netfilter.NF_ACCEPT)
		}
	}
}
