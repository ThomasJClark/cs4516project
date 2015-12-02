package main

import (
	"log"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("Starting up")

	//Call netFilter class here

	go processPackets()

	select {}

}
