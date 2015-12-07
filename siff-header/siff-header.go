package siff-header

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
)

// SIFF constants
const (
	IS_SIFF           layers.IPv4Flag = 1 << 1	// Specify a SIFF packet
	CAPABILITY_UPDATE layers.IPv4Flag = 1 << 0	// includes capability update
)

/* Adds the SIFF header to a packet, or modifies it in the case that it already
exists. Pass in the NFPacket, the flags (bitwise OR them if you need both), and
the capabilities and capability updates arrays. If only IS_SIFF is set, just fill
the last 4 bytes with dummy data, it'll be ignored. If you want to update specific
fields, then use the [update function name here] function */
func setSiffFields(packet *NFPacket, flags IPv4Flag, capabilities []IPv4Option, updoots []IPv4Option) {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	I can't be arsed for proper response outside the bounds of this project */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else  {
		continue
	}

	/* Modify the ip layer information */
	// compute new IHL and length
	var IHLchange uint8 = *ipLayer.IHL

	if flags == IS_SIFF {
		(*ipLayer).IHL = 6
	} else if flags == (IS_SIFF | CAPABILITY_UPDATE) {
		(*ipLayer).IHL = 7
	}

	/* change the total length by the change in IHL * 4 to convert from 
	32-bit words to bytes */
	IHLchange = *ipLayer.IHL - IHLchange
	if IHLchange != 0 {
		*ipLayer.length = *ipLayer.length + IHLchange * 4
	}

	(*ipLayer).Flags = flags

	// handle the options
	// add options
        if flags == (IS_SIFF | CAPABILITY_UPDATE) {
                *ipLayer.Options = capabilities
        } else {
                append(capabilities, updoots...)
		*ipLayer.Options = capabilities
        }

	// we're done
}


