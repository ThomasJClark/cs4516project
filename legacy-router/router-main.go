package main

import (
	"flag"
	"log"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("Starting up")

	drop := flag.Int("drop", 0, "The percent of packets to drop")
	flag.Parse()

	pDrop := *drop

	if pDrop > 100 {
		pDrop = 100
	} else if pDrop < 0 {
		pDrop = 0
	}

	//Call netFilter class here

	go processPackets(pDrop)

	select {}

}
