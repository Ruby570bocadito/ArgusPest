package main

import (
	"fmt"
	"os"
)

// Variables inyectadas en compilación
var C2URL       = "http://127.0.0.1:8443"
var AgentVersion = "2.0.0"

func main() {
	fmt.Fprintf(os.Stderr, "[stager] Argos Agent %s → C2: %s\n", AgentVersion, C2URL)
	// TODO: Implementar lógica de stager
}
