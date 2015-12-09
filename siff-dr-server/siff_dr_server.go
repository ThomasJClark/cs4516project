package main

import (
	"fmt"
	"log"
	"net/http"
)

/*
Create a simple HTTP server on port 8080 that serves a short piece of static
content.
*/
func main() {
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprint(res, "Sample server data")
		log.Println("Got req")
	})

	http.ListenAndServe(":8080", nil)
}
