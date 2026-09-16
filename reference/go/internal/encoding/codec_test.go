package encoding

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestPrimitiveEncoding(t *testing.T) {
	encoder := NewEncoder(128)
	encoder.Uint8(0x01)
	encoder.Uint16(0x0302)
	encoder.Uint32(0x07060504)
	encoder.Int64(-2)
	encoder.Bool(true)
	encoder.String("a\x00b")
	got, err := encoder.BytesResult()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 2, 3, 4, 5, 6, 7, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 3, 0, 0, 0, 'a', 0, 'b'}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding = %x, want %x", got, want)
	}
}

func TestVersionedEnvelope(t *testing.T) {
	encoder := NewEncoder(64)
	encoder.Versioned(3, 1, func(payload *Encoder) {
		payload.Uint16(0x0201)
		payload.Uint8(0xff)
	})
	data, err := encoder.BytesResult()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{3, 1, 3, 0, 0, 0, 1, 2, 0xff}
	if !bytes.Equal(data, want) {
		t.Fatalf("envelope = %x, want %x", data, want)
	}

	decoder := NewDecoder(append(data, 0xaa), Limits{MaxBytes: 64})
	version, payload := decoder.Versioned(2)
	if version != 3 || payload.Uint16() != 0x0201 {
		t.Fatalf("version=%d payload=%x", version, payload.Uint16())
	}
	if err := payload.Finish(); err != nil {
		t.Fatal(err)
	}
	if decoder.Uint8() != 0xaa || decoder.Remaining() != 0 {
		t.Fatal("envelope did not preserve following input")
	}
}

func TestDecoderRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		read func(*Decoder)
		want error
	}{
		{"truncated scalar", []byte{1}, func(d *Decoder) { d.Uint32() }, ErrMalformed},
		{"oversized bytes", []byte{5, 0, 0, 0, 1, 2, 3, 4, 5}, func(d *Decoder) { d.Bytes() }, ErrLimitExceeded},
		{"unsupported compat", []byte{2, 2, 0, 0, 0, 0}, func(d *Decoder) { d.Versioned(1) }, ErrUnsupportedVersion},
		{"truncated envelope", []byte{1, 1, 4, 0, 0, 0, 1}, func(d *Decoder) { d.Versioned(1) }, ErrMalformed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := NewDecoder(test.data, Limits{MaxBytes: 4})
			test.read(decoder)
			if !errors.Is(decoder.Finish(), test.want) {
				t.Fatalf("error = %v, want %v", decoder.Finish(), test.want)
			}
		})
	}
}

func TestEncoderLimitIsSticky(t *testing.T) {
	encoder := NewEncoder(4)
	encoder.Uint32(1)
	encoder.Uint8(2)
	encoder.Uint8(3)
	data, err := encoder.BytesResult()
	if !errors.Is(err, ErrLimitExceeded) || data != nil {
		t.Fatalf("data=%x error=%v", data, err)
	}
}

func TestCRC32C(t *testing.T) {
	for _, test := range []struct {
		payload string
		want    uint32
	}{
		{"foo bar baz", 4119623852},
		{"whiz bang boom", 2360230088},
	} {
		if got := CRC32C(0, []byte(test.payload)); got != test.want {
			t.Fatalf("CRC32C(%q) = %d, want %d", test.payload, got, test.want)
		}
	}

	first := CRC32C(math.MaxUint32, []byte("foo "))
	if got, want := CRC32C(first, []byte("bar baz")), CRC32C(math.MaxUint32, []byte("foo bar baz")); got != want {
		t.Fatalf("chained CRC32C = %d, want %d", got, want)
	}
}

func FuzzDecoder(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		decoder := NewDecoder(data, Limits{MaxBytes: 4096})
		decoder.Uint8()
		decoder.Uint16()
		decoder.Uint32()
		decoder.Uint64()
		decoder.Bool()
		decoder.Bytes()
		_ = decoder.String()
		decoder.Finish()
	})
}

func FuzzVersionedEnvelope(f *testing.F) {
	f.Add([]byte{1, 1, 0, 0, 0, 0})
	f.Add([]byte{3, 1, 3, 0, 0, 0, 1, 2, 0xff})
	f.Add([]byte{1, 2, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		decoder := NewDecoder(data, Limits{MaxBytes: 4096})
		_, payload := decoder.Versioned(3)
		payload.Uint64()
		payload.Bytes()
		payload.Finish()
		decoder.Finish()
	})
}
