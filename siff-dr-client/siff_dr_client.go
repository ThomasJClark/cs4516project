package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

/*
Return a full URL to request from the server.  This is determined based on
some environment variables that Docker sets.
*/
func getServerURL() string {
	addr := os.Getenv("SERVER_PORT_8080_TCP_ADDR")
	port := os.Getenv("SERVER_PORT_8080_TCP_PORT")

	return fmt.Sprintf("http://%s:%s", addr, port)
}

func main() {
	// Make an HTTP request to the server and print out the response
	res, err := http.Get(getServerURL())
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	// If the network is working, this should print:
	//     Got data: "Sample server data"
	log.Println("Got data:", fmt.Sprintf("\"%s\"", string(body)))
}
