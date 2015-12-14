package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

/*serveData creates a simple HTTP server on port 8080 that serves a short piece
of static content. This is run on the server machine.*/
func serveData() {
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		log.Print("Writing response")
		fmt.Fprint(res, "Sample server data")
	})

	log.Print("Serving data on :8080")

	http.ListenAndServe(":8080", nil)
}

/*requestData is a simple test function to request non-malicous data from
the server.  This is run on the client and the attacker machine.*/
func requestData() error {
	log.Println("Sending HTTP request to http://server:8080")

	// Make an HTTP request to the server and print out the response
	res, err := http.Get("http://server:8080")
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	log.Println("Reading response")

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		//		log.Fatal(err)
		return err
	}

	// If the network is working, this should print:
	//     Got data: "Sample server data"
	log.Println("Got data:", fmt.Sprintf("\"%s\"", string(body)))
	return nil
}

func measureThroughput(numRequests int) {
	success := 0.0
	var result error
	for i := 0; i < numRequests; i++ {
		result = requestData()
		if result == nil {
			success++
		} else {
			log.Println(result)
		}
	}
	successrate := success / float64(numRequests)
	log.Println("Measured success rate: ", successrate)
}
