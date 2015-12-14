package siffdr

import (
	"github.com/tatsushid/go-fastping"
	"net"
	"time"

	"log"
)


/*
DetectAttacks continuously pings a legacy router with the given addr until the
legacy router ceases to return pings, at which point the siff router running
DetectAttacks freaks the f*** out and declares the legacy router is under a DDOS
attack
*/
func DetectAttacks(callback func(), addr string){
	// create pinger and set the IP address if it is a real IP address
	// (otherwise throw a fit)
	p := fastping.NewPinger()
	ra, err := net.ResolveIPAddr("ip4:icmp", addr)
	if err != nil {
		log.Fatal(err)
	}
	p.AddIPAddr(ra)

	// received is used to tell when a ping has been successfully received
	// done is for when it hasn't
	// create timer here so that it can be used in different scopes and can just be reset later
	received := false
	done := make(chan bool)
	timer := time.NewTimer(100 * time.Second)

	// called when a ping response is received
	p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		log.Println("Got ping response from", addr, "in", rtt)
		received = true
	}

	// called at the end of a loop of p.RunLoop()
	p.OnIdle = func() {
		// if no ping has been received, exit and go back to the main function
		if !received {
			callback()
			done <- true
		}

		// reset the timer for the next run loop
		timer.Reset(time.Second)
		received = false
	}

	// GOOOOOOOOOOOOOOOOOOOOOO!!!!!!!!!!!!!!!!!!!!
	p.RunLoop()

	// when either there has been an error or a timeout (DDOS ATTACK!!!), leave
	select {
	case <-p.Done():
	case <-done:
	}

	// if something goes wrong, panic
	if p.Err() != nil {
		log.Fatal(p.Err())
	}
}