package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	in = flag.String("in", "in.png", "<file>\tInput image (JPEG/PNG format)")
	out = flag.String("out", "out.png", "<file>\tOutput image (PNG format)")

	embed = flag.Bool("embed", false, "Embed data into the image")
	extract = flag.Bool("extract", false, "Extract data from the image")
	data = flag.String("data", "embed.dat", "<file>\tData file to read/write embedded data")

	crypt = flag.Bool("crypt", false, "Encrypt/decrypt the data (depending on embed/extract)")
	keyin = flag.String("keyin", "", "<file>\tFile containing Key, IV, and Next")
	keyout = flag.String("keyout", "key.dat", "<file>\tFile to write new Key, IV, and Next")

	debug = flag.Bool("debug", false, "Enable debugging (hidden option)")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  This application is used for PNG image steganography.  It can\n")
		fmt.Fprintf(os.Stderr, "optionally encrypt/decrypt the data using AES.  If no keyin file\n")
		fmt.Fprintf(os.Stderr, "is specified in encryption mode, a new key will be generated.\n")
		fmt.Fprintf(os.Stderr, "  An image can hold approximately three bits per pixel with this\n")
		fmt.Fprintf(os.Stderr, "steganography scheme.  There is a certain amount of overhead\n")
		fmt.Fprintf(os.Stderr, "for storing lengths, keys, etc, so it may not be a good idea\n")
		fmt.Fprintf(os.Stderr, "to count on more than about two bits per pixel.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		for _,opt := range []string{"in","out","","embed","extract","data","","crypt","keyin","keyout"} {
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
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	// Sanity checks
	if *embed && *extract {
		log.Fatalf("Error: Cannot specify both --embed and --extract")
	}

	// Read in the image
	steg, err := Load(*in)
	if err != nil {
		log.Fatalf("Error: Unable to load %q: %s", *in, err)
	}

	// Choose which action to take
	if *embed {
		stat,err := os.Stat(*data)
		if err != nil {
			log.Fatalf("Error: Unable to load data from %q: %s", *data, err)
		}
		if 3*stat.Size > 2*int64(len(steg.Data)) {
			log.Printf("Warning: Image (%d pixels) may be too small for %d bytes of data",
				len(steg.Data)/3, stat.Size)
		}
		fin,err := os.Open(*data)
		if err != nil {
			log.Fatalf("Error: Unable to open data file %q: %s", *data, err)
		}

		buf := bytes.NewBuffer(nil)
		binary.Write(buf, binary.BigEndian, stat.Size)
		_,err = buf.ReadFrom(fin)
		if err != nil {
			log.Fatalf("Error: Unable to read data from %q: %s", *data, err)
		}
		// TODO(kevlar): size? padding? etc?

		if *crypt {

		}

		if buf.Len() > len(steg.Data) {
			log.Fatalf("Error: Unable to embed %d bytes into %d-pixel image",
				buf.Len(), len(steg.Data)/3)
		}
		steg.Embed(buf.Bytes())
	}

	if *extract {
		if *crypt {

		}

		fout,err := os.Create(*data)
		if err != nil {
			log.Fatalf("Error: Unable to open data file %q for writing: %s", *data, err)
		}

		buf := bytes.NewBuffer(steg.Data)
		var size int64
		binary.Read(buf, binary.BigEndian, &size)
		_,err = fout.Write(buf.Bytes()[0:size])
		if err != nil {
			log.Fatalf("Error: Unable to write data to %q: %s", *data, err)
		}
	}

	err = steg.WritePNG(*out)
	if err != nil {
		log.Fatalf("Error: Unable to write %q: %s", *out, err)
	}
}
