package main
import ("fmt"; "os")
var C2URL = "http://127.0.0.1:8443"
var AgentVersion = "2.0.0"
func main() { fmt.Fprintf(os.Stderr, "[unknown_type_xyz] Argos Agent %s\n", AgentVersion) }
