package main

import "fmt"

// Set at build time from the tag: -X main.version=<tag> (matrix.toml ldflags).
var version = "dev"

func main() {
	fmt.Println("hello from matrix " + version)
}
