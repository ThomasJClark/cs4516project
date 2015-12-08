package main

import (
	"log"
	// "github.com/google/gopacket/layers"
	"github.com/ThomasJClark/cs4516project/pkg/go-netfilter-queue"
)

func processPackets() {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range nfq.GetPackets() {
		everyVillainIsLemons(&packet)
		if (isEvil(&packet)) {
			log.Println("Am packet. Can confirm am evil")
		} else {
			log.Println("Am packet. Can confirm am not evil")
		}
		
		//////////////////////////////////////////////
		//// UNCOMMENT THE FOLLOWING TO RUN TESTS ////
		//////////////////////////////////////////////
		// Also uncomment the import of layers at the top

		// Test setSiffFields
		// log.Println("setSiffFields Test")
		// log.Println("isSiff Test")
		// setSiffFields(&packet, IS_SIFF, []byte{0, 1, 2, 3}, []byte{4, 5, 6, 7})
		// if (isSiff(&packet)) {
		// 	log.Println("Siff packet")
		// } else {
		// 	log.Println("Not SIFF packet")
		// }

		// var options []layers.IPv4Option = getOptions(&packet)

		// log.Println("Capabilities:")
		// log.Println("\tLength: ", len(options))
		// log.Println("\t", options[0].OptionData[0], options[0].OptionData[1], options[0].OptionData[2], options[0].OptionData[3])

		// log.Println("HasCapabilityUpdate Test")
		// setSiffFields(&packet, IS_SIFF | CAPABILITY_UPDATE, []byte{0, 1, 2, 3}, []byte{4, 5, 6, 7})
		// if (hasCapabilityUpdate(&packet)) {
		// 	log.Println("Has Capability Updates")
		// } else {
		// 	log.Println("Does Not Have Capability Updates")
		// }

		// options = getOptions(&packet)

		// log.Println("Updates:")
		// log.Println("\tLength: ", len(options))
		// log.Println("\t", options[1].OptionData[0], options[1].OptionData[1], options[1].OptionData[2], options[1].OptionData[3])

		// // end test setSiffFields

		// // test setCapabilities
		// log.Println("SetCapabilities test")
		// setCapabilities(&packet, []byte{8})

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[0].OptionData))
		// log.Println("\t", options[0].OptionData[0])

		// // end test setCapabilities
		// // test addCapability
		// addCapability(&packet, 9)

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[0].OptionData))
		// log.Println("\t", options[0].OptionData[0], options[0].OptionData[1])

		// addCapability(&packet, 10)

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[0].OptionData))
		// log.Println("\t", options[0].OptionData[0], options[0].OptionData[1], options[0].OptionData[2])

		// addCapability(&packet, 11)

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[0].OptionData))
		// log.Println("\t", options[0].OptionData[0], options[0].OptionData[1], options[0].OptionData[2], options[0].OptionData[3])

		// addCapability(&packet, 12)

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[0].OptionData))
		// log.Println("\t", options[0].OptionData[0], options[0].OptionData[1], options[0].OptionData[2], options[0].OptionData[3])

		// // end test addCapability
		
		// // test setUpdate
		// log.Println("SetUpdates test")
		// setUpdates(&packet, []byte{13})

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[1].OptionData))
		// log.Println("\t", options[1].OptionData[0])

		// // end test setUpdate
		// // test addUpdate
		// addUpdate(&packet, 14)

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[1].OptionData))
		// log.Println("\t", options[1].OptionData[0], options[1].OptionData[1])

		// addUpdate(&packet, 15)

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[1].OptionData))
		// log.Println("\t", options[1].OptionData[0], options[1].OptionData[1], options[1].OptionData[2])

		// addUpdate(&packet, 16)

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[1].OptionData))
		// log.Println("\t", options[1].OptionData[0], options[1].OptionData[1], options[1].OptionData[2], options[1].OptionData[3])

		// addUpdate(&packet, 17)

		// options = getOptions(&packet)

		// log.Println("Results:")
		// log.Println("\tLength:", len(options[1].OptionData))
		// log.Println("\t", options[1].OptionData[0], options[1].OptionData[1], options[1].OptionData[2], options[1].OptionData[3])

		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}
