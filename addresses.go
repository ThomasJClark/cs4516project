package cs4516project

import "net"

/*
Static IP addresses of all hosts in the network.  In case we ever change these,
programs should reference these variables instead of hard coding addresses.
*/
var (
	Server       = net.ParseIP("10.45.16.1")
	ServerRouter = net.ParseIP("10.45.16.2")
	SiffRouter1  = net.ParseIP("10.45.16.3")
	SiffRouter2  = net.ParseIP("10.45.16.4")
	LegacyRouter = net.ParseIP("10.45.16.5")
	ClientRouter = net.ParseIP("10.45.16.6")
	Client       = net.ParseIP("10.45.16.7")
)
