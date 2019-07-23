package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const timeout time.Duration = 1000*10

func main() {
	server := "google.co.in"
	//port := 443
	proxy := "http://localhost:2345"
	//proxy := ""

	// Prepare the client
	var client http.Client
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			panic("Error parsing proxy URL")
		}
		transport := http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{},
		}
		client = http.Client{
			Transport: &transport,
			Timeout:   time.Duration(time.Millisecond * timeout),
		}

	} else {
		client = http.Client{}
	}
	// Now we've proper client, with or without proxy

	//resp, err := client.Get(fmt.Sprintf("https://%v:%v", server,port))
	resp, err := client.Get(fmt.Sprintf("https://%v:443", server))
	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	fmt.Printf("Time to expiry for the certificate: %v\n", resp.TLS.PeerCertificates[0].NotAfter.Sub(time.Now()))
}
