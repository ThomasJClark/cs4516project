package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
)

// SIFF constants
const (
	EVIL		  layers.IPv4Flag = 1 << 2	// http://tools.ietf.org/html/rfc3514 ;)
							// also known as Every Villian Is Lemons
	IS_SIFF           layers.IPv4Flag = 1 << 1	// Specify a SIFF packet
	CAPABILITY_UPDATE layers.IPv4Flag = 1 << 0	// includes capability update
)

/* https://www.youtube.com/watch?v=SLqGwX5Jl60 */
func EveryVillianIsLemons(packet *netfilter.NFPacket) {
	var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := *packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        } else  {
                continue
        }

	(*ipLayer).flags = *ipLayer.flags | EVIL
}

/* Adds the SIFF header to a packet, or modifies it in the case that it already
exists. Pass in the NFPacket, the flags (bitwise OR them if you need both), and
the capabilities and capability updates arrays. If only IS_SIFF is set, just fill
the last 4 bytes with dummy data, it'll be ignored. If you want to update specific
fields, then use the [update function name here] function */
func setSiffFields(packet *netfilter.NFPacket, flags layers.IPv4Flag, capabilities []layers.IPv4Option, updoots []layers.IPv4Option) {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	I can't be arsed for proper response outside the bounds of this project */
	if layer := *packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else  {
		continue
	}

	/* Modify the ip layer information */
	// compute new IHL and length
	var IHLchange uint8 = *ipLayer.IHL

	if (flags & 0x03) == IS_SIFF {
		(*ipLayer).IHL = 6
	} else if (flags & 0x03) == (IS_SIFF | CAPABILITY_UPDATE) {
		(*ipLayer).IHL = 7
	}

	/* change the total length by the change in IHL * 4 to convert from 
	32-bit words to bytes */
	IHLchange = *ipLayer.IHL - IHLchange
	if IHLchange != 0 {
		*ipLayer.length = *ipLayer.length + IHLchange * 4
	}

	// set the flags, preserving the first flag bit in case it is used
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

func isEvil(packet *netfilter.NFPacket) bool {
        var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */ 
        if layer := *packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        } else  {
                return false
        }

        return (*ipLayer.IHL & (1 << 2)) == EVIL
}

func isSiff(packet *netfilter.NFPacket) bool {
	var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := *packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        } else  {
                return false
        }

	return (*ipLayer.IHL & 0x01) == IS_SIFF
}

func hasCapabilityUpdate(packet *netfilter.NFPacket) bool {
        var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := *packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        } else  {
                return false
        }

        return (*ipLayer.IHL & 0x03) == (IS_SIFF | CAPABILITY_UPDATE)
}

func getOptions(packet *netfilter.NFPacket) []layers.IPv4Option {
        var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        }

        return *ipLayer.Options
}
