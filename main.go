package main

import (
	"os"
	"fmt"
)

func chkerr(err os.Error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
}

func main() {
	key := []byte{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB,
		0xCC, 0xDD, 0xEE, 0xFF,
	}
	in, err := os.Open("in.txt"); chkerr(err)
	out, err := os.Create("out.enc"); chkerr(err)
	n, err := crypt(key, in, out); chkerr(err)
	fmt.Printf("Encrypted %d bytes\n", n)
	in.Close()
	out.Close()
}
