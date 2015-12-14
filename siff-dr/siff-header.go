package siffdr

import (
	"crypto/sha1"
	"log"

	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

// SIFF constants
const (
	Exp  uint8 = 1 << 2
	Evil uint8 = 1 << 3 // http://tools.ietf.org/html/rfc3514 ;)
	// also known as Every Villian Is Lemons
	IsSiff           uint8 = 1 << 1 // Specify a SIFF packet
	CapabilityUpdate uint8 = 1 << 0 // includes capability update
)

/* Adds the SIFF header to a packet, or modifies it in the case that it already
exists. Pass in the NFPacket, the flags (bitwise OR them if you need both), and
the capabilities and capability updates arrays. If only IsSiff is set, just fill
the last 4 bytes with dummy data, it'll be ignored. If you want to update specific
fields, then use the [update function name here] function */
func setSiffFields(packet *netfilter.NFPacket, flags uint8, capabilities []byte, updoots []byte) {
	var ipLayer *layers.IPv4
	var optionArray [3]layers.IPv4Option

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else {
		// maybe do something?
	}

	/* Modify the ip layer information */
	var IHLchange uint16 = uint16((*ipLayer).IHL)

	// compute new IHL and length
	if (flags&IsSiff) == IsSiff || (flags&Exp) == Exp {
		(*ipLayer).IHL = 8
	} else if (flags & (IsSiff | CapabilityUpdate)) == (IsSiff | CapabilityUpdate) {
		(*ipLayer).IHL = 10
	} else { // evil
		(*ipLayer).IHL = 5
	}

	IHLchange = uint16((*ipLayer).IHL) - IHLchange
	if IHLchange != 0 {
		(*ipLayer).Length = (*ipLayer).Length + IHLchange*4
	}

	/* change the total length by the change in IHL * 4 to convert from
	   32-bit words to bytes */
	(*ipLayer).Length = uint16((*ipLayer).IHL) * 4

	if (flags & Evil) == Evil {
		// set the evil flag. If we do this, we don't need to do anything else,
		// since evil packets are legacy, and don't have other flags
		(*ipLayer).Flags |= layers.IPv4EvilBit
	} else {
		// set the flags option
		var flagOption layers.IPv4Option
		flagOption.OptionType = 86
		flagOption.OptionLength = 4
		var flag_array [2]byte = [2]byte{0, 0}
		if (flags & Exp) == Exp {
			flag_array[0] = byte(Exp)
		}
		if (flags & CapabilityUpdate) == CapabilityUpdate {
			flag_array[0] = byte(IsSiff | CapabilityUpdate)
		} else if (flags & IsSiff) == IsSiff {
			flag_array[0] = byte(IsSiff)
		}
		flagOption.OptionData = flag_array[:]

		// handle the options
		var capOption layers.IPv4Option
		capOption.OptionType = 86

		capOption.OptionLength = 8
		var capabilities_array [6]byte
		for i, b := range capabilities {
			capabilities_array[i] = b
		}
		for i := len(capabilities); i < 6; i++ {
			capabilities_array[i] = 0
		}
		capOption.OptionData = capabilities_array[:]

		var updateOption layers.IPv4Option
		updateOption.OptionType = 86
		updateOption.OptionLength = 8

		var updates_array [6]byte
		for i, b := range updoots {
			updates_array[i] = b
		}
		for i := len(updoots); i < 6; i++ {
			updates_array[i] = 0
		}

		updateOption.OptionData = updoots

		optionArray[0] = flagOption
		optionArray[1] = capOption
		optionArray[2] = updateOption

		// add options
		if (uint8(flags) & 0x3) == uint8(IsSiff|CapabilityUpdate) {
			(*ipLayer).Options = optionArray[:3]
		} else if (uint8(flags)&0x2) == uint8(IsSiff) || (uint8(flags)&Exp) == Exp {
			(*ipLayer).Options = optionArray[:2]
		} else { // only flags options
			(*ipLayer).Options = optionArray[:1]
		}
	}

	// we're done
}

func isSiff(packet *netfilter.NFPacket) bool {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else {
		log.Println("Failed to get ip layer")
		return false
	}

	if len((*ipLayer).Options) < 2 { // need at least flags and cap for siff packet
		return false
	}

	return ((*ipLayer).Options[0].OptionData[0] & byte(IsSiff)) == byte(IsSiff)
}

func isExp(packet *netfilter.NFPacket) bool {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else {
		return false
	}

	return ((*ipLayer).Options[0].OptionData[0] & byte(Exp)) == byte(Exp)
}

func calcCapability(packet *netfilter.NFPacket) byte {
	var ipLayer *layers.IPv4
	/*Get the IPv4 layer, or ignore it if it doesn't exist. */
	if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
		// Append src and dest ip
		value := ipLayer.SrcIP.String() + ipLayer.DstIP.String()
		key := "This is a secure key right?"
		hash := sha1.New()
		// Get checksum of IPs with key
		checksum := hash.Sum([]byte(value + key))
		return checksum[len(checksum)-1]
	}
	var s byte
	return s
}

func shiftCapability(packet *netfilter.NFPacket) {
	var ipLayer *layers.IPv4
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	if len((*ipLayer).Options) == 0 {
		return
	}

	// Cut out empty options (more seem to get added for some reason at each hop)
	(*ipLayer).Options = (*ipLayer).Options[:(*ipLayer).IHL-6]
	// Shift all towards 0
	(*ipLayer).Options[1].OptionData = (*ipLayer).Options[1].OptionData[1:]
	(*ipLayer).Options[1].OptionData = append((*ipLayer).Options[1].OptionData, 9)
}

func hasCapabilityUpdate(packet *netfilter.NFPacket) bool {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else {
		return false
	}

	if len((*ipLayer).Options) != 3 { // When it has a capability update, need all three options
		return false
	}

	return ((*ipLayer).Options[0].OptionData[0] & byte(IsSiff|CapabilityUpdate)) == byte(IsSiff|CapabilityUpdate)
}

func getOptions(packet *netfilter.NFPacket) []layers.IPv4Option {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	return (*ipLayer).Options
}

func setCapabilities(packet *netfilter.NFPacket, capabilities []byte) {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	var option layers.IPv4Option
	option.OptionType = 86
	option.OptionLength = 8

	// set up a capabilities array
	var capabilities_array [6]byte
	for i, b := range capabilities {
		capabilities_array[i] = b
	}
	for i := len(capabilities); i < 6; i++ {
		capabilities_array[i] = 0
	}

	option.OptionData = capabilities_array[:]

	// add into Options
	if len((*ipLayer).Options) > 1 {
		(*ipLayer).Options[1] = option
	} else if len((*ipLayer).Options) == 1 {
		// var optionArray [1]layers.IPv4Option = [1]layers.IPv4Option{option}
		(*ipLayer).Options = append((*ipLayer).Options, option)
	}
}

func setUpdates(packet *netfilter.NFPacket, updates []byte) {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	var option layers.IPv4Option
	option.OptionType = 86
	option.OptionLength = 8

	// set up a capabilities array
	var updates_array [6]byte
	for i, b := range updates {
		updates_array[i] = b
	}
	for i := len(updates); i < 6; i++ {
		updates_array[i] = 0
	}

	option.OptionData = updates_array[:]

	// add into Options
	if len((*ipLayer).Options) > 3 {
		(*ipLayer).Options[2] = option
	} else if len((*ipLayer).Options) == 2 {
		// var optionArray [1]layers.IPv4Option = [1]layers.IPv4Option{option}
		(*ipLayer).Options = append((*ipLayer).Options, option)
	}
}

func getCapabilities(packet *netfilter.NFPacket) []byte {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	if (*ipLayer).Options != nil {
		return (*ipLayer).Options[1].OptionData
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
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	var count int = 0
	// count number of capabilities
	for _, b := range (*ipLayer).Options[2].OptionData {
		if b != 0 {
			count = count + 1
		}
	}

	if (*ipLayer).Options != nil {
		return (*ipLayer).Options[2].OptionData[:count]
	} else {
		return nil
	}
}

func addCapability(packet *netfilter.NFPacket, capability byte) {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	}

	if (*ipLayer).Options != nil {
		capabilities := getCapabilities(packet)
		capabilities = append([]byte{capability}, capabilities...)
		capabilities = capabilities[:6]
		(*ipLayer).Options[1].OptionData = capabilities[:]
	}
}

func addUpdate(packet *netfilter.NFPacket, capability byte) {
	var ipLayer *layers.IPv4

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	   I can't be arsed for proper response outside the bounds of this project */
	if (*ipLayer).Options != nil {

		var count int = 0
		// count number of capabilities
		for _, b := range (*ipLayer).Options[2].OptionData {
			if b != 0 {
				count = count + 1
			}
		}

		if count == 4 {
			// shift options forward
			var capability_array [6]byte
			capability_array[0] = (*ipLayer).Options[2].OptionData[1]
			capability_array[1] = (*ipLayer).Options[2].OptionData[2]
			capability_array[2] = (*ipLayer).Options[2].OptionData[3]
			capability_array[3] = capability
			// copy over two padding bytes
			capability_array[4] = (*ipLayer).Options[2].OptionData[4]
			capability_array[5] = (*ipLayer).Options[2].OptionData[5]

			(*ipLayer).Options[2].OptionData = capability_array[:]
		} else {
			var capability_array [6]byte
			var first_empty int = -1
			// copy slice in optionData to array
			for i, b := range (*ipLayer).Options[2].OptionData {
				capability_array[i] = b
				if b == 0 && first_empty == -1 {
					first_empty = i
				}
			}
			// store new capability
			capability_array[first_empty] = capability
			// set new slice
			(*ipLayer).Options[2].OptionData = capability_array[:]
		}
	}
}
