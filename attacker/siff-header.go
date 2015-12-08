package main

import (
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
func everyVillainIsLemons(packet *netfilter.NFPacket) {
	var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        } else  {
                // maybe do something?
        }

	(*ipLayer).Flags = (*ipLayer).Flags | EVIL
}

/* Adds the SIFF header to a packet, or modifies it in the case that it already
exists. Pass in the NFPacket, the flags (bitwise OR them if you need both), and
the capabilities and capability updates arrays. If only IS_SIFF is set, just fill
the last 4 bytes with dummy data, it'll be ignored. If you want to update specific
fields, then use the [update function name here] function */
func setSiffFields(packet *netfilter.NFPacket, flags layers.IPv4Flag, capabilities []byte, updoots []byte) {
	var ipLayer *layers.IPv4
	var optionArray [2]layers.IPv4Option

	/* Get the IPv4 layer, and if it doesn't exist, keep doing shit
	I can't be arsed for proper response outside the bounds of this project */
	if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipLayer = layer.(*layers.IPv4)
	} else  {
		// maybe do something?
	}

	/* Modify the ip layer information */
	// compute new IHL and length
	var IHLchange uint8 = (*ipLayer).IHL

	if (flags & 0x03) == IS_SIFF {
		(*ipLayer).IHL = 6
	} else if (flags & 0x03) == (IS_SIFF | CAPABILITY_UPDATE) {
		(*ipLayer).IHL = 7
	}

	/* change the total length by the change in IHL * 4 to convert from 
	32-bit words to bytes */
	IHLchange = (*ipLayer).IHL - IHLchange
	if IHLchange != 0 {
		(*ipLayer).Length = (*ipLayer).Length + uint16(IHLchange) * 4
	}

	// set the flags, preserving the first flag bit in case it is used
	(*ipLayer).Flags = flags

	// handle the options
	var capOption layers.IPv4Option
	capOption.OptionLength = uint8(len(capabilities))
	capOption.OptionData = capabilities

	var updateOption layers.IPv4Option
	updateOption.OptionLength = uint8(len(updoots))
	updateOption.OptionData = updoots

	optionArray[0] = capOption
	optionArray[1] = updateOption

	// add options
    if (uint8(flags) & 0x3) == uint8(IS_SIFF | CAPABILITY_UPDATE) {
    	var optionSlice []layers.IPv4Option = optionArray[:]
        (*ipLayer).Options = optionSlice
    } else if (uint8(flags) & 0x2) == uint8(IS_SIFF) {
		var optionSlice []layers.IPv4Option = optionArray[:1]
		(*ipLayer).Options = optionSlice
    }

	// we're done
}

func isEvil(packet *netfilter.NFPacket) bool {
        var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */ 
        if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        } else  {
                // maybe do something?
        }

        return (uint8((*ipLayer).IHL) & (1 << 2)) == uint8(EVIL)
}

func isSiff(packet *netfilter.NFPacket) bool {
	var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        } else  {
                return false
        }

	return (uint8((*ipLayer).IHL) & 0x02) == uint8(IS_SIFF)
}

func hasCapabilityUpdate(packet *netfilter.NFPacket) bool {
        var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        } else  {
                return false
        }

        return (uint8((*ipLayer).IHL) & 0x03) == uint8(IS_SIFF | CAPABILITY_UPDATE)
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

	option.OptionLength = uint8(len(capabilities))
	option.OptionData = capabilities[:]

	// add into Options
	(*ipLayer).Options[0] = option
}


func setUpdates(packet *netfilter.NFPacket, updates []byte) {
	 var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        }

	var option layers.IPv4Option

	option.OptionLength = uint8(len(updates))
	option.OptionData = updates[:]

	// add into Options
	(*ipLayer).Options[1] = option
}


func getCapabilities(packet *netfilter.NFPacket) []byte {
        var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        }

        if (*ipLayer).Options != nil {
		return (*ipLayer).Options[0].OptionData
	} else {
		return nil
	}
}

func getUpdates(packet *netfilter.NFPacket) []byte {
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

func addCapability(packet *netfilter.NFPacket, capability byte) {
	var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        }

	if (*ipLayer).Options != nil {
		if (*ipLayer).Options[0].OptionLength == 4 {
			// shift options forward
			var capability_array [4]byte
			capability_array[0] = (*ipLayer).Options[0].OptionData[1]
			capability_array[1] = (*ipLayer).Options[0].OptionData[2]
			capability_array[2] = (*ipLayer).Options[0].OptionData[3]
			capability_array[3] = capability

			(*ipLayer).Options[0].OptionData = capability_array[:]
		} else {
			var capability_array [4]byte
			// copy slice in optionData to array
			for i, b := range (*ipLayer).Options[0].OptionData {
				capability_array[i] = b
			}
			// store new capability
			capability_array[(*ipLayer).Options[0].OptionLength] = capability
			// set new slice
			(*ipLayer).Options[0].OptionLength = (*ipLayer).Options[0].OptionLength + 1
			(*ipLayer).Options[0].OptionData = capability_array[:(*ipLayer).Options[0].OptionLength]
		}
	}
}


func addUpdate(packet *netfilter.NFPacket, capability byte) {
	var ipLayer *layers.IPv4

        /* Get the IPv4 layer, and if it doesn't exist, keep doing shit
        I can't be arsed for proper response outside the bounds of this project */
        if layer := (*packet).Packet.Layer(layers.LayerTypeIPv4); layer != nil {
                ipLayer = layer.(*layers.IPv4)
        }

	if (*ipLayer).Options != nil {
		if (*ipLayer).Options[1].OptionLength == 4 {
			// shift options forward
			var capability_array [4]byte
			capability_array[0] = (*ipLayer).Options[1].OptionData[1]
			capability_array[1] = (*ipLayer).Options[1].OptionData[2]
			capability_array[2] = (*ipLayer).Options[1].OptionData[3]
			capability_array[3] = capability

			(*ipLayer).Options[1].OptionData = capability_array[:]
		} else {
			var capability_array [4]byte
			// copy slice in optionData to array
			for i, b := range (*ipLayer).Options[1].OptionData {
				capability_array[i] = b
			}
			// store new capability
			capability_array[(*ipLayer).Options[1].OptionLength] = capability
			// set new slice
			(*ipLayer).Options[1].OptionLength = (*ipLayer).Options[1].OptionLength + 1
			(*ipLayer).Options[1].OptionData = capability_array[:(*ipLayer).Options[1].OptionLength]
		}
	}
}
