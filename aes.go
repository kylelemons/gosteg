package main

import (
	"bytes"
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

func writekey(w io.Writer, pfx byte, key []byte) (n int, err os.Error) {
	var c int
	n,err = fmt.Fprintf(w, "%c ", pfx)
	if err != nil { return }
	for _,b := range key {
		c,err = fmt.Fprintf(w, "%02X", b)
		n += c
		if err != nil { return }
	}
	c,err = fmt.Fprint(w, "\n")
	n += c
	return
}

func (e *Encryption) WriteTo(w io.Writer) (n int, err os.Error) {
	var c int
	n,err = writekey(w, 'K', e.Key)
	if err != nil { return }
	c,err = writekey(w, 'I', e.IV)
	n += c
	if err != nil { return }
	c,err = writekey(w, 'N', e.Next)
	n += c
	return
}

func readkey(r io.Reader, pfx byte) (key []byte, err os.Error) {
	var b,s string
	_,err = fmt.Fscanln(r, &b, &s)
	if len(b) != 1 || pfx != b[0] {
		return nil, fmt.Errorf("Expected key label %c, got %s", pfx, b)
	}
	if len(s) != 32 && len(s) != 48 && len(s) != 64 {
		return nil, fmt.Errorf("AES requires 128, 192, or 256-bit keys, got %d for keylabel %c",
			4*len(s), pfx)
	}
	buf := bytes.NewBufferString(s)
	var read int
	for buf.Len() > 0 {
		_,err = fmt.Fscanf(buf, "%2X", &read)
		if err != nil {
			break
		}
		key = append(key, byte(read))
	}
	return
}

func (e *Encryption) ReadFrom(r io.Reader) (err os.Error) {
	var k []byte
	k,err = readkey(r, 'K')
	if err != nil { return }
	e.Key = k
	e.Size = len(k)

	k,err = readkey(r, 'I')
	if err != nil { return }
	e.IV = k
	if len(k) != e.Size {
		return fmt.Errorf("IV and Key must have identical lengths: Expected %d, got %d",
			8*len(e.Key), 8*len(e.IV))
	}

	k,err = readkey(r, 'N')
	if err != nil { return }
	e.Next = k
	if len(k) != e.Size {
		return fmt.Errorf("Next and Key must have identical lengths: Expected %d, got %d",
			8*len(e.Key), 8*len(e.Next))
	}
	return
}

func Randomize(bytes []byte) os.Error {
	_, err := rand.Read(bytes)
	if err != nil {
		return err
	}
	return nil
}

func (e *Encryption) Rotate() {
	copy(e.IV, e.Key)
	copy(e.Key, e.Next)
	Randomize(e.Next)
}

func (e *Encryption) Encrypt(infile io.Reader, outfile io.Writer) (int, os.Error) {
	// Construct an AES block cipher with the given key
	blk, err := aes.NewCipher(e.Key)
	if err != nil {
		return 0, err
	}

	// Initialization Vector - never reuse for same key
	bm := cipher.NewCBCEncrypter(blk, e.IV)

	return cryptstream(bm, infile, outfile, true)
}

func (e *Encryption) Decrypt(infile io.Reader, outfile io.Writer) (int, os.Error) {
	// Construct an AES block cipher with the given key
	blk, err := aes.NewCipher(e.Key)
	if err != nil {
		return 0, err
	}

	bm := cipher.NewCBCDecrypter(blk, e.IV)

	return cryptstream(bm, infile, outfile, false)
}

func cryptstream(bm cipher.BlockMode, in io.Reader, out io.Writer, enc bool) (int, os.Error) {
	plaintext := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize)
	total := 0
	pad := 0

	delayed := false

	for {
		n, err := in.Read(plaintext)
		if err == os.EOF {
			if n == 0 {
				break
			}
		} else if err != nil {
			return total, err
		}
		if enc {
			pad = aes.BlockSize - n
			for i := 0; i < pad; i++ {
				plaintext[aes.BlockSize-i-1] = byte(pad)
			}
		} else if delayed {
			n, err := out.Write(ciphertext)
			if err != nil {
				return total, err
			}
			total += n
		}

		bm.CryptBlocks(ciphertext, plaintext)
		if enc {
			n, err = out.Write(ciphertext)
			if err != nil {
				return total, err
			}
			total += n
		} else {
			delayed = true
		}
	}
	if pad == 0 && enc {
		for i := 0; i < aes.BlockSize; i++ {
			plaintext[i] = aes.BlockSize
		}
		bm.CryptBlocks(ciphertext, plaintext)
		n, err := out.Write(ciphertext)
		if err != nil {
			return total, err
		}
		total += n
	}
	// last block for decryption
	if !enc && delayed {
		strip := int(ciphertext[len(ciphertext)-1])
		if strip <= aes.BlockSize {
			ciphertext = ciphertext[0:len(ciphertext)-strip]
			n, err := out.Write(ciphertext)
			if err != nil {
				return total, err
			}
			total += n
		} else if strip > aes.BlockSize {
			return total, fmt.Errorf("Decryption failed (wrong key?)")
		}
	}

	return total, nil
}
