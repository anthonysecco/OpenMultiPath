// Command omp-pep runs the split-TCP accelerator; see internal/pep.
package main

import (
	"flag"
	"log"

	"github.com/anthonysecco/OpenMultiPath/internal/pep"
)

func main() {
	addr := flag.String("listen", "0.0.0.0:9050", "address for redirected connections (see deploy/omp-pep-rules)")
	flag.Parse()
	log.Fatal(pep.Run(*addr))
}
