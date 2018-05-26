package main

import (
	"crypto/sha256"
	"fmt"
	"time"
)

func main() {
	data := make([]byte, 100*1024*1024)

	start := time.Now()
	hash := sha256.Sum256(data)
	elapsed := time.Now().Sub(start)

	fmt.Printf("%x (%v)\n", hash, elapsed)
}
