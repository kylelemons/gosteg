package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"io"
)

func hexprint(name string, buf []byte) {
	fmt.Printf("%-10s: ", name)
	for _,b := range buf {
		fmt.Printf("%02X", b)
	}
	fmt.Println("")
}

func crypt(key []byte, infile io.Reader, outfile io.Writer) (int, os.Error) {
	// Construct an AES block cipher with the given key
	blk, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}

	hexprint("Key", key)

	// Initialization Vector - never reuse for same key
	iv := make([]byte, aes.BlockSize)
	n, err := rand.Read(iv)
	if err != nil || n != aes.BlockSize {
		if err == nil {
			err = os.NewError(fmt.Sprintf("Only generated %d random iv bits, expected %d",
				n, aes.BlockSize))
		}
		return 0, err
	}

	hexprint("IV", iv)

	bm := cipher.NewCBCEncrypter(blk, iv)

	plaintext := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize)
	total := 0
	pad := 0

	for {
		n, err := infile.Read(plaintext)
		if err == os.EOF {
			if n == 0 {
				break
			}
		} else if err != nil {
			return total, err
		}
		if n != aes.BlockSize {
			fmt.Printf("Warning: Read %d bytes, expected %d\n", n, aes.BlockSize)
		}
		pad = aes.BlockSize - n
		for i := 0; i < pad; i++ {
			plaintext[aes.BlockSize-i-1] = byte(pad)
		}
		hexprint("Plain", plaintext)
		bm.CryptBlocks(ciphertext, plaintext)
		hexprint("Cipher", ciphertext)
		n, err = outfile.Write(ciphertext)
		if err != nil {
			return total, err
		}
		total += n
		fmt.Printf("Info: Wrote %d bytes\n", n)
	}
	// Always have padding bytes
	if pad == 0 {
		for i := 0; i < aes.BlockSize; i++ {
			plaintext[i] = aes.BlockSize
		}
		bm.CryptBlocks(ciphertext, plaintext)
		n, err = outfile.Write(ciphertext)
		if err != nil {
			return total, err
		}
		total += n
		fmt.Printf("Info: Wrote %d extra bytes\n", n)
	}

	fmt.Printf("Info: Written %d encrypted bytes\n", total)

	return total, nil
}
