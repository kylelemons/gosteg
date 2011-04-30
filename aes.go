package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"io"
	"fmt"
)

type Encryption struct {
	Size int
	Key  []byte
	IV   []byte
	Next []byte
}

func NewEncryption(bits int) *Encryption {
	switch bits {
		case 128:
		case 192:
		case 256:
			break;
		default:
			panic("AES only supports 128, 192, and 256-bit modes")
	}
	return &Encryption{
		Size: bits/8,
		Key:  make([]byte, bits/8),
		IV:   make([]byte, bits/8),
		Next: make([]byte, bits/8),
	}
}

func hexprint(out io.Writer, title string, bytes []byte) {
	fmt.Fprintf(out, "%6s : ", title)
	for _,b := range bytes {
		fmt.Fprintf(out, "%02X", b)
	}
	fmt.Fprint(out, "\n")
}

func (e *Encryption) Show() {
	hexprint(os.Stdout, "Key", e.Key)
	hexprint(os.Stdout, "IV", e.IV)
	hexprint(os.Stdout, "Next", e.Next)
}

func Randomize(bytes []byte) os.Error {
	_, err := rand.Read(bytes)
	if err != nil {
		return err
	}
	return nil
}

func (e *Encryption) Encrypt(infile io.Reader, outfile io.Writer) (int, os.Error) {
	// Construct an AES block cipher with the given key
	blk, err := aes.NewCipher(e.Key)
	if err != nil {
		return 0, err
	}

	// Initialization Vector - never reuse for same key
	bm := cipher.NewCBCEncrypter(blk, e.IV)

	return cryptstream(bm, infile, outfile)
}

func (e *Encryption) Decrypt(infile io.Reader, outfile io.Writer) (int, os.Error) {
	// Construct an AES block cipher with the given key
	blk, err := aes.NewCipher(e.Key)
	if err != nil {
		return 0, err
	}

	// Initialization Vector - never reuse for same key
	bm := cipher.NewCBCDecrypter(blk, e.IV)

	return cryptstream(bm, infile, outfile)
}

func cryptstream(bm cipher.BlockMode, infile io.Reader, outfile io.Writer) (int, os.Error) {
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
		pad = aes.BlockSize - n
		for i := 0; i < pad; i++ {
			plaintext[aes.BlockSize-i-1] = byte(pad)
		}
		bm.CryptBlocks(ciphertext, plaintext)
		n, err = outfile.Write(ciphertext)
		if err != nil {
			return total, err
		}
		total += n
	}
	if pad == 0 {
		for i := 0; i < aes.BlockSize; i++ {
			plaintext[i] = aes.BlockSize
		}
		bm.CryptBlocks(ciphertext, plaintext)
		n, err := outfile.Write(ciphertext)
		if err != nil {
			return total, err
		}
		total += n
	}

	return total, nil
}
