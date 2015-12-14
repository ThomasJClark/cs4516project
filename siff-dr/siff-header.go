package siffdr

import (
	"bytes"
	"crypto/sha1"
	"log"
	"os"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

// SIFF constants
const (
	Evil uint8 = 1 << 3 // http://tools.ietf.org/html/rfc3514 ;)
	// also known as Every Villian Is Lemons
	Exp              uint8 = 1 << 2
	IsSiff           uint8 = 1 << 1 // Specify a SIFF packet
	CapabilityUpdate uint8 = 1 << 0 // includes capability update
)

type SiffOption struct {
	flags        byte
	reserved     byte
	capabilities []byte
	updates      []byte
}

func (s *SiffOption) serializeOption() []byte {
	buf := bytes.Buffer{}
	buf.WriteByte(s.flags)
	buf.WriteByte(0)
	buf.Write(s.capabilities)
	if (s.flags & CapabilityUpdate) == CapabilityUpdate {
		buf.Write(s.updates)
	}

	return buf.Bytes()
}

func deserializeOption(arr []byte) SiffOption {
	opt := SiffOption{
		flags:    arr[0],
		reserved: 0,
	}

	if (opt.flags&IsSiff) == IsSiff || (opt.flags&Exp) == Exp {
		opt.capabilities = arr[2:6]
	}
	if (opt.flags & CapabilityUpdate) == CapabilityUpdate {
		opt.updates = arr[6:10]
	}
	return opt
}

/* Adds the SIFF header to a packet, or modifies it in the case that it already
exists. Pass in the NFPacket, the flags (bitwise OR them if you need both), and
the capabilities and capability updates arrays. If only IsSiff is set, just fill
the last 4 bytes with dummy data, it'll be ignored. If you want to update specific
fields, then use the [update function name here] function */
func setSiffFields(packet *netfilter.NFPacket, flags uint8, capabilities []byte, updoots []byte) {
	var ipLayer *layers.IPv4
	var option [1]layers.IPv4Option
	option[0].OptionType = 86
	option[0].OptionLength = 8

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else {
		// maybe do something?
	}

	/* Modify the ip layer information */
	var IHLchange uint16 = uint16(ipLayer.IHL)

	// compute new IHL and length
	if (flags & CapabilityUpdate) == CapabilityUpdate {
		ipLayer.IHL = 8
		option[0].OptionLength = 12
	} else if (flags&IsSiff) == IsSiff || (flags&Exp) == Exp {
		ipLayer.IHL = 7
	} else {
		ipLayer.IHL = 5
	}

	IHLchange = uint16(ipLayer.IHL) - IHLchange
	if IHLchange != 0 {
		ipLayer.Length += IHLchange * 4
	}

	if (flags & Evil) == Evil {
		// set the evil flag. If we do this, we don't need to do anything else,
		// since evil packets are legacy, and don't have other flags
		ipLayer.Flags |= layers.IPv4EvilBit
	} else {
		// set the flags option
		option[0].OptionData = []byte{0, 0}
		if (flags & Exp) == Exp {
			option[0].OptionData[0] = byte(Exp)
		}
		if (flags & CapabilityUpdate) == CapabilityUpdate {
			option[0].OptionData[0] |= byte(IsSiff | CapabilityUpdate)
		} else if (flags & IsSiff) == IsSiff {
			option[0].OptionData[0] |= byte(IsSiff)
		}

		// handle the options
		if flags != 0 {
			for _, b := range capabilities {
				option[0].OptionData = append(option[0].OptionData, b)
			}
		}

		if (flags & CapabilityUpdate) == CapabilityUpdate {
			for _, b := range updoots {
				option[0].OptionData = append(option[0].OptionData, b)
			}
		}
		// add options
		if flags != 0 {
			ipLayer.Options = append([]layers.IPv4Option{option[0]}, ipLayer.Options...)
		}
	}

	// we're done
}

func isSiff(packet *netfilter.NFPacket) bool {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else {
		log.Println("Failed to get ip layer")
		return false
	}

	if len(ipLayer.Options) == 0 {
		return false
	}

	opt := deserializeOption(ipLayer.Options[0].OptionData)
	return (opt.flags & byte(IsSiff)) == byte(IsSiff)
}

func isExp(packet *netfilter.NFPacket) bool {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else {
		return false
	}

	if len(ipLayer.Options) == 0 {
		return false
	}

	opt := deserializeOption(ipLayer.Options[0].OptionData)
	return (opt.flags & byte(Exp)) == byte(Exp)
}

func calcCapability(packet *netfilter.NFPacket) byte {
	var ipLayer *layers.IPv4
	key, _ := os.Hostname() // No one will ever guess this!

	/* Get the IPv4 layer, or ignore it if it doesn't exist. */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)

		/* The capability value is the last byte of a SHA1 hash of the source
		IP, destination IP, and a secret key. This allows the router to
		identify flows it has previously approved without storing per-flow
		state. */
		hash := sha1.New()
		value := ipLayer.SrcIP.String() + ipLayer.DstIP.String() + key
		sum := hash.Sum([]byte(value))[hash.Size()-1]
		return sum
	}
	var s byte
	return s
}

func shiftCapability(packet *netfilter.NFPacket) {
	var ipLayer *layers.IPv4
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	if len((*ipLayer).Options) == 0 {
		return
	}

	opt := deserializeOption(ipLayer.Options[0].OptionData)

	// Cut out empty options (more seem to get added for some reason at each hop)
	//(*ipLayer).Options = (*ipLayer).Options[:(*ipLayer).IHL-6]
	// Shift all towards 0
	for i := 0; i < 3; i++ {
		opt.capabilities[i] = opt.capabilities[i+1]
	}
	opt.capabilities[3] = 0
	ipLayer.Options[0].OptionData = opt.serializeOption()
}

func hasCapabilityUpdate(packet *netfilter.NFPacket) bool {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else {
		return false
	}

	if len(ipLayer.Options) == 0 {
		return false
	}
	opt := deserializeOption(ipLayer.Options[0].OptionData)
	return (opt.flags & CapabilityUpdate) == CapabilityUpdate
}

func getOptions(packet *netfilter.NFPacket) []layers.IPv4Option {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	return ipLayer.Options
}

func getCapabilities(packet *netfilter.NFPacket) []byte {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	opt := deserializeOption(ipLayer.Options[0].OptionData)
	if ipLayer.Options != nil {
		return opt.capabilities
	} else {
		return nil
	}
}

func getUpdates(packet *netfilter.NFPacket) []byte {
	var ipLayer *layers.IPv4

	if !hasCapabilityUpdate(packet) {
		return nil
	}

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	opt := deserializeOption(ipLayer.Options[0].OptionData)
	if ipLayer.Options != nil {
		return opt.updates
	} else {
		return nil
	}
}

func addCapability(packet *netfilter.NFPacket, capability byte) {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	if (*ipLayer).Options != nil {
		opt := deserializeOption(ipLayer.Options[0].OptionData)
		opt.capabilities = append([]byte{capability}, opt.capabilities...)
		opt.capabilities = opt.capabilities[:4]
		ipLayer.Options[0].OptionData = opt.serializeOption()
	}
}

func addUpdate(packet *netfilter.NFPacket, capability byte) {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if ipLayer.Options != nil {
		opt := deserializeOption(ipLayer.Options[0].OptionData)
		opt.updates = append([]byte{capability}, opt.updates...)
		opt.updates = opt.updates[:4]
		ipLayer.Options[0].OptionData = opt.serializeOption()
	}
}

/*
Reverse the capability to read it to be sent back
*/
func reverseCapability(capability []byte) {
	//find end of array
	length := len(capability)
	for length = len(capability) - 1; capability[length] == 0 && length > 0; length-- {
		//do nothing
	}

	for i := 0; i <= int(length/2); i++ {
		temp := capability[length-i]
		capability[length-i] = capability[i]
		capability[i] = temp
	}
}
