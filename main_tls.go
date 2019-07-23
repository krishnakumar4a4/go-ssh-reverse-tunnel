package main

import (
	"crypto/tls"
	"fmt"
)

func main() {
	_, err := tls.Dial("tcp","localhost:2345", nil)
	if err != nil {
		fmt.Println("Error connecting, err ", err)
	}
}
