package main

import (
	"fmt"
	"net/http"
)

/*
Create a simple HTTP server on port 8080 that serves a short piece of static
content.
*/
func main() {
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprint(res, "Sample server data")
	})

	http.ListenAndServe(":8080", nil)
}
