package steg

import (
	"os"
	"image"
	"image/png"
)

// Silently accept JPEG image import too
import _ "image/jpeg"

type Steg struct {
	Image image.Image
	Data []byte
}

func Load(filename string) (*Steg, os.Error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	img, _, err := image.Decode(file)
	if err != nil {
		return nil, err
	}

	bounds := img.Bounds().Size()
	pixels := bounds.X * bounds.Y
	png := image.NewRGBA64(bounds.X, bounds.Y)

	steg := &Steg{
		Image: png,
		Data: make([]byte, (3*pixels)/8),
	}

	var accum, bits, i uint16
	for y := 0; y < bounds.Y; y++ {
		for x := 0; x < bounds.X; x++ {
			png.Set(x,y, img.At(x,y))
			col := png.Pix[y*png.Stride+x]
			accum <<= 3
			accum |= (col.R << 2) & 4
			accum |= (col.G << 1) & 2
			accum |= (col.B << 0) & 1
			bits += 3
			if bits >= 8 {
				b := (accum >> (bits - 8)) & 0xFF
				steg.Data[i] = uint8(b)
				i++
				bits -= 8
			}
		}
	}
	return steg, nil
}

func (s *Steg) Embed(data []byte) {
	offset := 0
	copy(s.Data, data)
	data = s.Data
	nextbits := func(col image.RGBA64Color) image.RGBA64Color {
		b := int(data[offset/8]) << 8;
		if offset%8 > 5 {
			b |= int(data[offset/8 + 1])
		}
		tri := (b >> uint(13 - offset%8)) & 7
		col.R = (col.R & 0xFFFE) | uint16((tri >> 2) & 1)
		col.G = (col.G & 0xFFFE) | uint16((tri >> 1) & 1)
		col.B = (col.B & 0xFFFE) | uint16(tri & 1)
		offset += 3
		return col
	}
	png := s.Image.(*image.RGBA64)
	for i := 0; i < len(png.Pix); i++ {
		png.Pix[i] = nextbits(png.Pix[i])
	}
}

func (s *Steg) WritePNG(filename string) os.Error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	err = png.Encode(file, s.Image)
	if err != nil {
		return err
	}
	return nil
}
