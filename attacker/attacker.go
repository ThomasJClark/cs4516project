package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {

	//Start up netfilter queue
	go processPackets()

	// Make an HTTP request to the server and print out the response
	// url := fmt.Sprintf("http://%s:8080", cs4516project.Server)
	res, err := http.Get("http://notserver:8080")
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
	log.Println("Client got data:", fmt.Sprintf("\"%s\"", string(body)))
}
