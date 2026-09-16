package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	wire "github.com/otuschhoff/go-librados/internal/encoding"
)

func TestEntityNameEncoding(t *testing.T) {
	tests := []struct {
		fixture string
		name    EntityName
	}{
		{"entity-name-mon-new.bin", EntityName{Type: EntityMonitor, Num: NewEntity}},
		{"entity-name-client-1.bin", EntityName{Type: EntityClient, Num: 1}},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			want := readFixture(t, test.fixture)
			encoder := wire.NewEncoder(9)
			test.name.Encode(encoder)
			got, err := encoder.BytesResult()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("entity name = %x, want %x", got, want)
			}
			decoder := wire.NewDecoder(got, wire.Limits{})
			if decoded := DecodeEntityName(decoder); decoded != test.name {
				t.Fatalf("decoded = %#v", decoded)
			}
			if err := decoder.Finish(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestP04FeatureMasks(t *testing.T) {
	if FeatureOSDMapEncoding != 0x0f04088090212a04 {
		t.Fatalf("OSDMap encoding features = %#x", FeatureOSDMapEncoding)
	}
	if FeatureMonitorClient != 0x2f070a92d235ea24 {
		t.Fatalf("monitor client features = %#x", FeatureMonitorClient)
	}
	required := FeatureMonitorNames | FeatureMonitorEncoding | FeaturePGID64 | FeatureMessageAddress2 | FeatureServerNautilusMask
	if !FeatureMonitorClient.Has(required) {
		t.Fatalf("monitor client features %#x lack required map formats %#x", FeatureMonitorClient, required)
	}
	if !FeatureOSDClient.Has(FeatureCRUSHV2) {
		t.Fatalf("OSD client features %#x lack CRUSH_V2", FeatureOSDClient)
	}
	if FeatureMonitorClient.Has(FeatureReserved) {
		t.Fatal("monitor client must not advertise Ceph's impossible reserved bit")
	}
}

func TestCephAddressFixtureParity(t *testing.T) {
	address, err := IPv4EntityAddr(AddressLegacy, 5, netip.MustParseAddrPort("127.0.1.2:2"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		fixture  string
		features GlobalFeatures
	}{
		{"entity-addr-ipv4-legacy.bin", 0},
		{"entity-addr-ipv4-modern.bin", FeatureMessageAddress2 | FeatureServerNautilusMask},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			assertAddressEncoding(t, address, test.features, readFixture(t, test.fixture))
		})
	}

	blank := EntityAddr{Family: linuxAFUnspec, SocketData: make([]byte, 26)}
	encoder := wire.NewEncoder(256)
	if err := (EntityAddrVec{blank, blank}).Encode(encoder, FeatureMessageAddress2); err != nil {
		t.Fatal(err)
	}
	got, err := encoder.BytesResult()
	if err != nil {
		t.Fatal(err)
	}
	want := readFixture(t, "entity-addrvec-modern.bin")
	if !bytes.Equal(got, want) {
		t.Fatalf("address vector = %x, want %x", got, want)
	}
	decoded, err := DecodeEntityAddrVec(wire.NewDecoder(want, wire.Limits{MaxBytes: 256}), 2)
	if err != nil || len(decoded) != 2 {
		t.Fatalf("decoded = %#v, error = %v", decoded, err)
	}
}

func TestIPv6AddressFixtureParity(t *testing.T) {
	endpoint := netip.MustParseAddrPort("[2001:db8::1234]:3300")
	address, err := IPv6EntityAddr(AddressV2, 7, endpoint, 0x01020304, 0x05060708)
	if err != nil {
		t.Fatal(err)
	}
	want := readFixture(t, "entity-addr-ipv6-modern.bin")
	assertAddressEncoding(t, address, FeatureMessageAddress2, want)
	decoded, err := DecodeEntityAddr(wire.NewDecoder(want, wire.Limits{MaxBytes: 64}))
	if err != nil {
		t.Fatal(err)
	}
	gotEndpoint, ok := decoded.AddrPort()
	if !ok || gotEndpoint != endpoint || decoded.Type != AddressV2 || decoded.Nonce != 7 {
		t.Fatalf("decoded = %#v endpoint=%v", decoded, gotEndpoint)
	}
	if got := binary.LittleEndian.Uint32(decoded.SocketData[2:6]); got != 0x01020304 {
		t.Fatalf("flow info = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(decoded.SocketData[22:26]); got != 0x05060708 {
		t.Fatalf("scope ID = %#x", got)
	}
}

func TestParseEntityAddr(t *testing.T) {
	tests := []struct {
		input    string
		kind     AddressType
		endpoint string
		nonce    uint32
	}{
		{input: "192.0.2.1", kind: AddressV2, endpoint: "192.0.2.1:0"},
		{input: "v1:192.0.2.1:6800/7", kind: AddressLegacy, endpoint: "192.0.2.1:6800", nonce: 7},
		{input: "any:[2001:db8::1]:3300/4294967295", kind: AddressAny, endpoint: "[2001:db8::1]:3300", nonce: math.MaxUint32},
		{input: "v2:2001:db8::1", kind: AddressV2, endpoint: "[2001:db8::1]:0"},
	}
	for _, test := range tests {
		address, err := ParseEntityAddr(test.input)
		if err != nil {
			t.Fatalf("ParseEntityAddr(%q): %v", test.input, err)
		}
		endpoint, ok := address.AddrPort()
		if !ok || address.Type != test.kind || endpoint.String() != test.endpoint || address.Nonce != test.nonce {
			t.Fatalf("ParseEntityAddr(%q) = %+v endpoint=%s", test.input, address, endpoint)
		}
	}
}

func TestParseEntityAddrRejectsMalformedInput(t *testing.T) {
	for _, input := range []string{"", "hostname:6800", "v3:192.0.2.1:6800", "192.0.2.1:", "192.0.2.1/", "192.0.2.1/1/2", "192.0.2.1/4294967296", "[2001:db8::1", "[2001:db8::1]:65536"} {
		if _, err := ParseEntityAddr(input); !errors.Is(err, ErrInvalidAddress) {
			t.Fatalf("ParseEntityAddr(%q) error=%v", input, err)
		}
	}
}

func assertAddressEncoding(t *testing.T, address EntityAddr, features GlobalFeatures, want []byte) {
	t.Helper()
	encoder := wire.NewEncoder(256)
	if err := address.Encode(encoder, features); err != nil {
		t.Fatal(err)
	}
	got, err := encoder.BytesResult()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("address = %x, want %x", got, want)
	}
	decoded, err := DecodeEntityAddr(wire.NewDecoder(want, wire.Limits{MaxBytes: 256}))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != address.Type || decoded.Nonce != address.Nonce || decoded.Family != address.Family || !bytes.Equal(decoded.SocketData, address.SocketData) {
		t.Fatalf("decoded = %#v, want %#v", decoded, address)
	}
}

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "p01", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func FuzzEntityAddr(f *testing.F) {
	for _, name := range []string{"entity-addr-ipv4-legacy.bin", "entity-addr-ipv4-modern.bin"} {
		f.Add(readFixture(f, name))
	}
	f.Add([]byte{})
	f.Add([]byte{1, 1, 1, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		address, err := DecodeEntityAddr(wire.NewDecoder(data, wire.Limits{MaxBytes: 4096}))
		if err == nil && len(address.SocketData) > 26 {
			t.Fatalf("decoded %d socket bytes", len(address.SocketData))
		}
	})
}

func FuzzEntityAddrVec(f *testing.F) {
	f.Add(readFixture(f, "entity-addrvec-modern.bin"))
	f.Add([]byte{})
	f.Add([]byte{2, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		addresses, err := DecodeEntityAddrVec(wire.NewDecoder(data, wire.Limits{MaxBytes: 4096}), ^uint32(0))
		if err == nil && uint64(len(addresses)) > uint64(len(data)) {
			t.Fatalf("decoded %d addresses", len(addresses))
		}
	})
}

func TestModernIPv4AddressEncoding(t *testing.T) {
	address, err := IPv4EntityAddr(AddressV2, 5, netip.MustParseAddrPort("127.0.1.2:2"))
	if err != nil {
		t.Fatal(err)
	}
	encoder := wire.NewEncoder(64)
	if err := address.Encode(encoder, FeatureMessageAddress2); err != nil {
		t.Fatal(err)
	}
	data, err := encoder.BytesResult()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 1, 1, 28, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 16, 0, 0, 0, 2, 0, 0, 2, 127, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(data, want) {
		t.Fatalf("address = %x, want %x", data, want)
	}
	decoded, err := DecodeEntityAddr(wire.NewDecoder(data, wire.Limits{MaxBytes: 64}))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, ok := decoded.AddrPort()
	if !ok || endpoint != netip.MustParseAddrPort("127.0.1.2:2") || decoded.Type != AddressV2 || decoded.Nonce != 5 {
		t.Fatalf("decoded = %#v endpoint=%v", decoded, endpoint)
	}
}

func TestAddressAnyRequiresNautilusIncarnation(t *testing.T) {
	address := EntityAddr{Type: AddressAny, Family: linuxAFUnspec, SocketData: make([]byte, 26)}
	encode := func(features GlobalFeatures) []byte {
		encoder := wire.NewEncoder(64)
		if err := address.Encode(encoder, FeatureMessageAddress2|features); err != nil {
			t.Fatal(err)
		}
		data, err := encoder.BytesResult()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	withoutIncarnation, err := DecodeEntityAddr(wire.NewDecoder(encode(FeatureServerNautilus), wire.Limits{MaxBytes: 64}))
	if err != nil || withoutIncarnation.Type != AddressLegacy {
		t.Fatalf("without incarnation = %#v, %v", withoutIncarnation, err)
	}
	withIncarnation, err := DecodeEntityAddr(wire.NewDecoder(encode(FeatureServerNautilusMask), wire.Limits{MaxBytes: 64}))
	if err != nil || withIncarnation.Type != AddressAny {
		t.Fatalf("with incarnation = %#v, %v", withIncarnation, err)
	}
}

func TestAddressVectorLimitAndMarker(t *testing.T) {
	decoder := wire.NewDecoder([]byte{2, 2, 0, 0, 0}, wire.Limits{MaxBytes: 64})
	if _, err := DecodeEntityAddrVec(decoder, 1); !errors.Is(err, wire.ErrLimitExceeded) {
		t.Fatalf("limit error = %v", err)
	}
	decoder = wire.NewDecoder([]byte{3}, wire.Limits{MaxBytes: 64})
	if _, err := DecodeEntityAddrVec(decoder, 1); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("marker error = %v", err)
	}
	decoder = wire.NewDecoder([]byte{2, 0xff, 0xff, 0xff, 0xff}, wire.Limits{MaxBytes: 64})
	if _, err := DecodeEntityAddrVec(decoder, ^uint32(0)); !errors.Is(err, wire.ErrMalformed) {
		t.Fatalf("impossible count error = %v", err)
	}
}

func TestLegacyAddressVectorPreservesFollowingInput(t *testing.T) {
	address, err := IPv4EntityAddr(AddressLegacy, 5, netip.MustParseAddrPort("127.0.1.2:2"))
	if err != nil {
		t.Fatal(err)
	}
	encoder := wire.NewEncoder(256)
	if err := (EntityAddrVec{address}).Encode(encoder, 0); err != nil {
		t.Fatal(err)
	}
	encoder.Uint8(0xaa)
	data, err := encoder.BytesResult()
	if err != nil {
		t.Fatal(err)
	}
	decoder := wire.NewDecoder(data, wire.Limits{MaxBytes: 256})
	addresses, err := DecodeEntityAddrVec(decoder, 1)
	if err != nil || len(addresses) != 1 {
		t.Fatalf("addresses=%#v error=%v", addresses, err)
	}
	if decoder.Uint8() != 0xaa || decoder.Remaining() != 0 {
		t.Fatal("legacy vector consumed following input")
	}
}

func TestModernAddressNormalizesShortSockaddr(t *testing.T) {
	tests := []struct {
		name       string
		payload    []byte
		family     uint16
		dataLength int
	}{
		{"empty", []byte{1, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, linuxAFUnspec, 26},
		{"short IPv4", []byte{1, 1, 1, 16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 2, 127}, linuxAFInet, 14},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, err := DecodeEntityAddr(wire.NewDecoder(test.payload, wire.Limits{MaxBytes: 64}))
			if err != nil {
				t.Fatal(err)
			}
			if address.Family != test.family || len(address.SocketData) != test.dataLength {
				t.Fatalf("address = %#v", address)
			}
			encoder := wire.NewEncoder(64)
			if err := address.Encode(encoder, FeatureMessageAddress2); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWireErrnoPreservesLinuxNumber(t *testing.T) {
	if WireErrno(-110).Class() != ErrorTimeout || WireErrno(-2).Class() != ErrorNotFound || WireErrno(-999).Class() != ErrorUnknown {
		t.Fatal("unexpected wire errno classification")
	}
	encoder := wire.NewEncoder(4)
	WireErrno(-110).Encode(encoder)
	data, err := encoder.BytesResult()
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeWireErrno(wire.NewDecoder(data, wire.Limits{})); got != -110 {
		t.Fatalf("decoded errno = %d", got)
	}
}
