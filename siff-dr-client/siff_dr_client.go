package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/ThomasJClark/cs4516project"
)

func main() {
	// Make an HTTP request to the server and print out the response
	url := fmt.Sprintf("http://%s:8080", cs4516project.Server)
	res, err := http.Get(url)
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
