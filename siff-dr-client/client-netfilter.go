package main

import (
	"bytes"
	"log"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range nfq.GetPackets() {
		log.Println("Adding SIFF headers")
		var empty []byte
		var empty2 []byte
		var flags layers.IPv4Flag
		flags |= IS_SIFF
		setSiffFields(&packet, flags, empty, empty2)

		if isSiff(&packet) {
			log.Println("Packet is SIFF")
		}

		var ipLayer *layers.IPv4
		/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
		   I can't be arsed for proper response outside the bounds of this project */
		if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
			ipLayer = layer.(*layers.IPv4)
		} else {
			// maybe do something?
			log.Println("Failed to get ip layer")
		}

		serializedPacket, err := Serialize(ipLayer)
		if err != nil {
			log.Println("Failed to serialize packet, dropping")
			packet.SetVerdict(netfilter.NF_DROP)
		} else {
			packet.SetResult(netfilter.NF_ACCEPT, serializedPacket)
		}
	}
}
