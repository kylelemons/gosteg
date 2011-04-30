package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"kylelemons/steg"
)

// TODO(kevlar): Open all files at the beginning for error reporting

var (
	in = flag.String("in", "", "<file>\tInput image (JPEG/PNG format)")
	out = flag.String("out", "", "<file>\tOutput image (PNG format)")

	embed = flag.String("embed", "", "<file>\tEmbed data into the image from this file")
	extract = flag.String("extract", "", "<file>\tExtract data from the image to this file")

	crypt = flag.Bool("crypt", false, "Encrypt/decrypt the data (based on mode)")
	keyin = flag.String("keyin", "", "<file>\tFile containing Key, IV, and Next")
	keyout = flag.String("keyout", "key.dat", "key.dat\tFile to write new Key, IV, and Next")
	rotate = flag.Bool("rotate", false, "Rotate keys before encryption")

	raw = flag.Bool("raw", false, "Extract data without headers (hidden option)")
	debug = flag.Bool("debug", false, "Enable debugging (hidden option)")
	help = flag.Bool("help", false, "Show help message (hidden option)")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  This application is used for PNG image steganography.  It can\n")
		fmt.Fprintf(os.Stderr, "optionally encrypt/decrypt the data using AES.  If no keyin file\n")
		fmt.Fprintf(os.Stderr, "is specified in encryption mode, a new key will be generated.\n")
		fmt.Fprintf(os.Stderr, "  An image can hold approximately three bits per pixel with this\n")
		fmt.Fprintf(os.Stderr, "steganography scheme.  There is a certain amount of overhead\n")
		fmt.Fprintf(os.Stderr, "for storing lengths, keys, etc.  Keep this in mind when choosing\n")
		fmt.Fprintf(os.Stderr, "an image size for embedding.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		for _,opt := range []string{"in","out","",
									"embed","extract","data","",
									"crypt","keyin","keyout","rotate"} {
			f := flag.Lookup(opt)
			if f != nil {
				opts := ""
				usage := f.Usage
				if strings.Contains(usage, "\t") {
					pieces := strings.Split(usage, "\t", 2)
					usage = pieces[1]
					opts = pieces[0]
				}
				fmt.Fprintf(os.Stderr, "  --%-8s %-8s %s\n", f.Name, opts, usage)
			} else {
				fmt.Fprintf(os.Stderr, "\n")
			}
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	// Sanity checks
	if len(*embed) != 0 && len(*extract) != 0 {
		log.Fatalf("Error: Cannot specify both --embed and --extract")
	}

	// Read in the image
	if len(*in) == 0 {
		log.Fatalf("Error: Must specify input image with --in")
	}
	img, err := steg.Load(*in)
	if err != nil {
		log.Fatalf("Error: Unable to load %q: %s", *in, err)
	}

	// Choose which action to take
	if len(*embed) > 0 {
		stat,err := os.Stat(*embed)
		if err != nil {
			log.Fatalf("Error: Unable to stat data file %q: %s", *embed, err)
		}
		fin,err := os.Open(*embed)
		if err != nil {
			log.Fatalf("Error: Unable to open data file %q: %s", *embed, err)
		}

		buf := bytes.NewBuffer(nil)

		if *crypt {
			enc := steg.NewEncryption(256)
			// Get the keys (either generate or read from file)
			if len(*keyin) == 0 {
				steg.Randomize(enc.Key)
				steg.Randomize(enc.IV)
				steg.Randomize(enc.Next)
			} else {
				kin,err := os.Open(*keyin)
				if err != nil {
					log.Fatalf("Error: Unable to open key file %q: %s", *keyin, err)
				}
				err = enc.ReadFrom(kin)
				if err != nil {
					log.Fatalf("Error: Unable to load key from %q: %s", *keyin, err)
				}
				kin.Close()
			}
			if *rotate {
				enc.Rotate()
			}

			cbuf := bytes.NewBuffer(nil)
			_,err = enc.Encrypt(fin, cbuf)
			if err != nil {
				log.Fatalf("Error: Unable to encrypt data from %q: %s", *embed, err)
			}
			binary.Write(buf, binary.BigEndian, int64(cbuf.Len()))
			log.Printf("Embedding %d bytes of encrypted data\n", cbuf.Len())
			buf.ReadFrom(cbuf)

			kout,err := os.Create(*keyout)
			if err != nil {
				log.Fatalf("Error: Unable to write key to %q: %s", *keyout, err)
			}
			enc.WriteTo(kout)
			kout.Close()
		} else {
			binary.Write(buf, binary.BigEndian, stat.Size)
			log.Printf("Embedding %d bytes of data\n", stat.Size)
			_,err = buf.ReadFrom(fin)
			if err != nil {
				log.Fatalf("Error: Unable to read data from %q: %s", *embed, err)
			}
		}

		if buf.Len() > len(img.Data) {
			log.Fatalf("Error: Unable to embed %d bytes into %d-pixel image",
				buf.Len(), len(img.Data)/3)
		}
		img.Embed(buf.Bytes())

		err = img.WritePNG(*out)
		if err != nil {
			log.Fatalf("Error: Unable to write %q: %s", *out, err)
		}
	}

	if len(*extract) > 0 {
		buf := bytes.NewBuffer(img.Data)

		if !*raw {
			var size int64
			binary.Read(buf, binary.BigEndian, &size)
			buf.Truncate(int(size))
		}

		if *crypt {
			enc := steg.NewEncryption(256)
			if len(*keyin) == 0 {
				log.Fatalf("Error: Must specify decryption key file with --keyin")
			}
			kin,err := os.Open(*keyin)
			if err != nil {
				log.Fatalf("Error: Unable to open key file %q: %s", *keyin, err)
			}
			err = enc.ReadFrom(kin)
			if err != nil {
				log.Fatalf("Error: Unable to load key from %q: %s", *keyin, err)
			}
			kin.Close()

			dbuf := bytes.NewBuffer(nil)
			_,err = enc.Decrypt(buf, dbuf)
			if err != nil {
				log.Fatalf("Error: Unable to decrypt data from %q: %s", *extract, err)
			}
			log.Printf("Decrypted %d bytes\n", dbuf.Len())
			buf = dbuf
		}

		fout,err := os.Create(*extract)
		if err != nil {
			log.Fatalf("Error: Unable to open data file %q for writing: %s", *extract, err)
		}

		_,err = fout.Write(buf.Bytes())
		if err != nil {
			log.Fatalf("Error: Unable to write data to %q: %s", *extract, err)
		}
	}
}
