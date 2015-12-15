package main

import (
	"flag"
	"log"
	"os/exec"
	"time"

	"github.com/ThomasJClark/cs4516project/siff-dr"
)

func main() {

	modeStr := flag.String("mode", "", "What kind of node in the network to "+
		"act like (client, server, siff-router, legacy-router, or attacker)")

	drop := flag.Int("drop", 0, "The percent of packets to drop in legacy mode")

	altCmd := flag.String("alt", "", "The command to run when a neighboring "+
		"legacy router is under attack")

	flag.Parse()

	log.SetFlags(log.Ltime)
	log.Println("STARTING")

	updates := make(chan siffdr.PendingCU, 2)
	capability := make(chan siffdr.Capability, 2)

	switch *modeStr {
	case "client":
		go siffdr.ProcessOutputPackets(updates, capability)
		go siffdr.ProcessInputPackets(updates, capability)
		time.Sleep(5)

		for _ = range time.NewTicker(time.Second).C {
			t := time.Now()
			requestData()
			log.Println("RTT:", time.Since(t))
		}

	case "attacker":
		go siffdr.MakePacketsEvil()
		time.Sleep(1)
		requestData()

	case "server":
		go siffdr.ProcessOutputPackets(updates, capability)
		go siffdr.ProcessInputPackets(updates, capability)
		serveData()

	case "siff-router":
		go siffdr.ProcessForwardPackets()
		if *altCmd != "" {
			time.Sleep(1)
			log.Println("detecting attacks...")
			siffdr.DetectAttacks(func() {
				log.Println("Running:", *altCmd)

				cmd := exec.Command("bash", "-c", *altCmd)
				if output, err := cmd.CombinedOutput(); err != nil {
					log.Print(err)
					log.Fatal("output:", string(output))
				} else {
					log.Println("output:", string(output))
				}
			}, "legacy-router")
		}
		select {}

	case "legacy-router":
		siffdr.DropPackets(*drop)

	default:
		flag.Usage()
	}
}
