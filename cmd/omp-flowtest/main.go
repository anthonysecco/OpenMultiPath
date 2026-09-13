// Command omp-flowtest is the home end of the ompd-native UDP flow test
// (internal/diag/flowtest.go, D-053) that backs the "Measure Link Speed"
// button.
package main

import (
	"context"
	"flag"
	"log"
	"net"

	"github.com/anthonysecco/OpenMultiPath/internal/diag"
)

func main() {
	listen := flag.String("listen", "10.20.1.1:5202", "address to serve the flow test on; reachable only through the WireGuard tunnels")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("omp-flowtest: resolving %q: %v", *listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("omp-flowtest: listening on %s: %v", *listen, err)
	}
	defer conn.Close()

	log.Printf("omp-flowtest: serving on %s", *listen)
	log.Fatal(diag.ServeFlowTest(context.Background(), conn))
}
