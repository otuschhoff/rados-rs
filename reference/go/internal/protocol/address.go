package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	wire "github.com/otuschhoff/go-librados/internal/encoding"
)

const (
	linuxAFUnspec      = 0
	linuxAFInet        = 2
	linuxAFInet6       = 10
	legacySockaddrSize = 128
)

var ErrInvalidAddress = errors.New("invalid entity address")

type AddressType uint32

const (
	AddressNone   AddressType = 0
	AddressLegacy AddressType = 1
	AddressV2     AddressType = 2
	AddressAny    AddressType = 3
	AddressCIDR   AddressType = 4
)

// EntityAddr preserves the Linux-shaped sockaddr bytes following sa_family.
// SocketData has length 14 for IPv4 and 26 for IPv6 or unspecified addresses.
type EntityAddr struct {
	Type       AddressType
	Nonce      uint32
	Family     uint16
	SocketData []byte
}

func ParseEntityAddr(value string) (EntityAddr, error) {
	addressType := AddressV2
	for prefix, candidate := range map[string]AddressType{"v1:": AddressLegacy, "v2:": AddressV2, "any:": AddressAny} {
		if strings.HasPrefix(value, prefix) {
			addressType = candidate
			value = strings.TrimPrefix(value, prefix)
			break
		}
	}
	if value == "-" {
		return EntityAddr{Type: AddressNone, Family: linuxAFUnspec, SocketData: make([]byte, 26)}, nil
	}
	endpointText, nonceText, hasNonce := strings.Cut(value, "/")
	if hasNonce && (nonceText == "" || strings.Contains(nonceText, "/")) {
		return EntityAddr{}, ErrInvalidAddress
	}
	var nonce uint64
	var err error
	if hasNonce {
		nonce, err = strconv.ParseUint(nonceText, 10, 32)
		if err != nil {
			return EntityAddr{}, fmt.Errorf("%w: invalid nonce", ErrInvalidAddress)
		}
	}
	endpoint, err := parseEntityEndpoint(endpointText)
	if err != nil {
		return EntityAddr{}, err
	}
	if endpoint.Addr().Is4() {
		return IPv4EntityAddr(addressType, uint32(nonce), endpoint)
	}
	return IPv6EntityAddr(addressType, uint32(nonce), endpoint, 0, 0)
}

func parseEntityEndpoint(value string) (netip.AddrPort, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		return netip.AddrPortFrom(address, 0), nil
	}
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: invalid endpoint", ErrInvalidAddress)
	}
	return endpoint, nil
}

func IPv4EntityAddr(addressType AddressType, nonce uint32, endpoint netip.AddrPort) (EntityAddr, error) {
	address := endpoint.Addr().Unmap()
	if !address.Is4() {
		return EntityAddr{}, fmt.Errorf("%w: expected IPv4", ErrInvalidAddress)
	}
	data := make([]byte, 14)
	binary.BigEndian.PutUint16(data[:2], endpoint.Port())
	value := address.As4()
	copy(data[2:6], value[:])
	return EntityAddr{Type: addressType, Nonce: nonce, Family: linuxAFInet, SocketData: data}, nil
}

func IPv6EntityAddr(addressType AddressType, nonce uint32, endpoint netip.AddrPort, flowInfo, scopeID uint32) (EntityAddr, error) {
	address := endpoint.Addr()
	if !address.Is6() || address.Is4In6() || address.Zone() != "" {
		return EntityAddr{}, fmt.Errorf("%w: expected unzoned IPv6", ErrInvalidAddress)
	}
	data := make([]byte, 26)
	binary.BigEndian.PutUint16(data[:2], endpoint.Port())
	binary.LittleEndian.PutUint32(data[2:6], flowInfo)
	value := address.As16()
	copy(data[6:22], value[:])
	binary.LittleEndian.PutUint32(data[22:26], scopeID)
	return EntityAddr{Type: addressType, Nonce: nonce, Family: linuxAFInet6, SocketData: data}, nil
}

func (address EntityAddr) AddrPort() (netip.AddrPort, bool) {
	switch address.Family {
	case linuxAFInet:
		if len(address.SocketData) != 14 {
			return netip.AddrPort{}, false
		}
		var value [4]byte
		copy(value[:], address.SocketData[2:6])
		return netip.AddrPortFrom(netip.AddrFrom4(value), binary.BigEndian.Uint16(address.SocketData[:2])), true
	case linuxAFInet6:
		if len(address.SocketData) != 26 {
			return netip.AddrPort{}, false
		}
		var value [16]byte
		copy(value[:], address.SocketData[6:22])
		return netip.AddrPortFrom(netip.AddrFrom16(value), binary.BigEndian.Uint16(address.SocketData[:2])), true
	default:
		return netip.AddrPort{}, false
	}
}

func (address EntityAddr) Encode(encoder *wire.Encoder, features GlobalFeatures) error {
	if err := address.validate(); err != nil {
		return err
	}
	if !features.Has(FeatureMessageAddress2) {
		encoder.Uint32(0)
		encoder.Uint32(address.Nonce)
		legacy := make([]byte, legacySockaddrSize)
		binary.BigEndian.PutUint16(legacy[:2], address.Family)
		copy(legacy[2:], address.SocketData)
		encoder.Raw(legacy)
		return nil
	}

	addressType := address.Type
	if addressType == AddressAny && !features.Has(FeatureServerNautilusMask) {
		addressType = AddressLegacy
	}
	encoder.Uint8(1)
	encoder.Versioned(1, 1, func(payload *wire.Encoder) {
		payload.Uint32(uint32(addressType))
		payload.Uint32(address.Nonce)
		payload.Uint32(uint32(2 + len(address.SocketData)))
		payload.Uint16(address.Family)
		payload.Raw(address.SocketData)
	})
	return nil
}

func DecodeEntityAddr(decoder *wire.Decoder) (EntityAddr, error) {
	marker := decoder.Uint8()
	if err := decoder.Finish(); err != nil {
		return EntityAddr{}, err
	}
	return decodeEntityAddrAfterMarker(decoder, marker)
}

func decodeEntityAddrAfterMarker(decoder *wire.Decoder, marker uint8) (EntityAddr, error) {
	switch marker {
	case 0:
		decoder.Raw(3)
		nonce := decoder.Uint32()
		sockaddr := decoder.Raw(legacySockaddrSize)
		if err := decoder.Finish(); err != nil {
			return EntityAddr{}, err
		}
		family := binary.BigEndian.Uint16(sockaddr[:2])
		addressType := AddressLegacy
		if family == linuxAFUnspec {
			addressType = AddressNone
		}
		dataLength, err := socketDataLength(family)
		if err != nil {
			return EntityAddr{}, err
		}
		return EntityAddr{Type: addressType, Nonce: nonce, Family: family, SocketData: append([]byte(nil), sockaddr[2:2+dataLength]...)}, nil
	case 1:
		_, payload := decoder.Versioned(1)
		addressType := AddressType(payload.Uint32())
		nonce := payload.Uint32()
		encodedLength := payload.Uint32()
		if encodedLength == 0 {
			if err := payload.Finish(); err != nil {
				return EntityAddr{}, err
			}
			return EntityAddr{Type: addressType, Nonce: nonce, SocketData: make([]byte, 26)}, decoder.Finish()
		}
		if encodedLength < 2 {
			return EntityAddr{}, fmt.Errorf("%w: sockaddr length %d", ErrInvalidAddress, encodedLength)
		}
		family := payload.Uint16()
		dataLength := encodedLength - 2
		maximum, err := socketDataLength(family)
		if err != nil || dataLength > uint32(maximum) {
			return EntityAddr{}, fmt.Errorf("%w: family %d length %d", ErrInvalidAddress, family, encodedLength)
		}
		data := make([]byte, maximum)
		copy(data, payload.Raw(dataLength))
		if err := payload.Finish(); err != nil {
			return EntityAddr{}, err
		}
		if err := decoder.Finish(); err != nil {
			return EntityAddr{}, err
		}
		return EntityAddr{Type: addressType, Nonce: nonce, Family: family, SocketData: data}, nil
	default:
		return EntityAddr{}, fmt.Errorf("%w: marker %d", ErrInvalidAddress, marker)
	}
}

func (address EntityAddr) validate() error {
	length, err := socketDataLength(address.Family)
	if err != nil {
		return err
	}
	if len(address.SocketData) != length {
		return fmt.Errorf("%w: family %d requires %d socket bytes, got %d", ErrInvalidAddress, address.Family, length, len(address.SocketData))
	}
	return nil
}

func socketDataLength(family uint16) (int, error) {
	switch family {
	case linuxAFInet:
		return 14, nil
	case linuxAFUnspec, linuxAFInet6:
		return 26, nil
	default:
		return 0, fmt.Errorf("%w: unsupported Linux address family %d", ErrInvalidAddress, family)
	}
}

type EntityAddrVec []EntityAddr

func (addresses EntityAddrVec) Encode(encoder *wire.Encoder, features GlobalFeatures) error {
	if !features.Has(FeatureMessageAddress2) {
		address := EntityAddr{Family: linuxAFUnspec, SocketData: make([]byte, 26)}
		for _, candidate := range addresses {
			if candidate.Type == AddressLegacy {
				address = candidate
				break
			}
		}
		return address.Encode(encoder, 0)
	}
	if uint64(len(addresses)) > uint64(^uint32(0)) {
		return wire.ErrLimitExceeded
	}
	encoder.Uint8(2)
	encoder.Uint32(uint32(len(addresses)))
	for _, address := range addresses {
		if err := address.Encode(encoder, features); err != nil {
			return err
		}
	}
	return nil
}

func DecodeEntityAddrVec(decoder *wire.Decoder, maxAddresses uint32) (EntityAddrVec, error) {
	marker := decoder.Uint8()
	if err := decoder.Finish(); err != nil {
		return nil, err
	}
	if marker < 2 {
		address, err := decodeEntityAddrAfterMarker(decoder, marker)
		if err != nil {
			return nil, err
		}
		return EntityAddrVec{address}, nil
	}
	if marker > 2 {
		return nil, fmt.Errorf("%w: address vector marker %d", ErrInvalidAddress, marker)
	}
	count := decoder.Uint32()
	if count > maxAddresses {
		return nil, wire.ErrLimitExceeded
	}
	// Every modern vector element needs at least a marker byte. Prove the
	// allocation against available input even when the caller's limit is broad.
	if uint64(count) > decoder.Remaining() {
		return nil, wire.ErrMalformed
	}
	addresses := make(EntityAddrVec, 0, count)
	for range count {
		address, err := DecodeEntityAddr(decoder)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, decoder.Finish()
}
