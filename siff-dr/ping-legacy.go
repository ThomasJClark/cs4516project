package siffdr

import (
	"github.com/tatsushid/go-fastping"
	"net"
	"time"

	"log"
)


func DetectAttacks(callback func(), addr string){
	p := fastping.NewPinger()
	ra, err := net.ResolveIPAddr("ip4:icmp", addr)
	if err != nil {
		log.Fatal(err)
	}
	p.AddIPAddr(ra)

	received := false
	done := make(chan bool)
	timer := time.NewTimer(100 * time.Second)

	p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		log.Println("Got ping response from", addr, "in", rtt)
		received = true
	}

	p.OnIdle = func() {
		if !received {
			callback()
			done <- true
		}

		timer.Reset(time.Second)
		received = false
	}

	p.RunLoop()

	select {
	case <-p.Done():
	case <-done:
	}

	if p.Err() != nil {
		log.Fatal(p.Err())
	}
}