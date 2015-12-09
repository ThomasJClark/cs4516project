package siffdr

import (
	"bytes"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func serialize(ipLayer *layers.IPv4) ([]byte, error) {
	/*Write the IPv4 header into a gopacket buffer*/
	buf := gopacket.NewSerializeBuffer()
	err := ipLayer.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: true})
	if err != nil {
		return nil, err
	}

	/*Write the gopacket buffer and the payload into a byte buffer, concatenating
	  the entire packet together.*/
	var buf2 bytes.Buffer
	buf2.Write(buf.Bytes())
	buf2.Write(ipLayer.Payload)

	return buf2.Bytes(), nil
}

/*hostname returns the hostname of the given IP address if available, or the
IP address otherwise. If the hostname is found, the IP address is also appended
in parentheses.

I just took this from my AITF project*/
func hostname(ip net.IP) string {
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return ip.String()
	}

	return fmt.Sprintf("%s (%s)", names[0], ip.String())
}
