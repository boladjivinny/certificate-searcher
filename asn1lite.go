package certificate_searcher

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/teamnsrg/zcrypto/x509/pkix"
	"math"
)

var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

type tagAndLength struct {
	class, tag, length int
	isCompound         bool
}

// A StructuralError suggests that the ASN.1 data is valid, but the Go type
// which is receiving it doesn't match.
type StructuralError struct {
	Msg string
}

func (e StructuralError) Error() string { return "asn1: structure error: " + e.Msg }

// A SyntaxError suggests that the ASN.1 data is invalid.
type SyntaxError struct {
	Msg string
}

func (e SyntaxError) Error() string { return "asn1: syntax error: " + e.Msg }

// parseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice. It returns the value and the new offset.
func parseBase128Int(bytes []byte, initOffset int) (ret, offset int, err error) {
	offset = initOffset
	var ret64 int64
	for shifted := 0; offset < len(bytes); shifted++ {
		// 5 * 7 bits per byte == 35 bits of data
		// Thus the representation is either non-minimal or too large for an int32
		if shifted == 5 {
			err = StructuralError{"base 128 integer too large"}
			return
		}
		ret64 <<= 7
		b := bytes[offset]
		ret64 |= int64(b & 0x7f)
		offset++
		if b&0x80 == 0 {
			ret = int(ret64)
			// Ensure that the returned value fits in an int on all platforms
			if ret64 > math.MaxInt32 {
				err = StructuralError{"base 128 integer too large"}
			}
			return
		}
	}
	err = SyntaxError{"truncated base 128 integer"}
	return
}

// parseTagAndLength parses an ASN.1 tag and length pair from the given offset
// into a byte slice. It returns the parsed data and the new offset. SET and
// SET OF (tag 17) are mapped to SEQUENCE and SEQUENCE OF (tag 16) since we
// don't distinguish between ordered and unordered objects in this code.
func parseTagAndLength(bytes []byte, initOffset int) (ret tagAndLength, offset int, err error) {
	offset = initOffset
	// parseTagAndLength should not be called without at least a single
	// byte to read. Thus this check is for robustness:
	if offset >= len(bytes) {
		err = errors.New("asn1: internal error in parseTagAndLength")
		return
	}
	b := bytes[offset]
	offset++
	ret.class = int(b >> 6)
	ret.isCompound = b&0x20 == 0x20
	ret.tag = int(b & 0x1f)

	// If the bottom five bits are set, then the tag number is actually base 128
	// encoded afterwards
	if ret.tag == 0x1f {
		ret.tag, offset, err = parseBase128Int(bytes, offset)
		if err != nil {
			return
		}
		// Tags should be encoded in minimal form.
		if ret.tag < 0x1f {
			err = SyntaxError{"non-minimal tag"}
			return
		}
	}
	if offset >= len(bytes) {
		err = SyntaxError{"truncated tag or length"}
		return
	}
	b = bytes[offset]
	offset++
	if b&0x80 == 0 {
		// The length is encoded in the bottom 7 bits.
		ret.length = int(b & 0x7f)
	} else {
		// Bottom 7 bits give the number of length bytes to follow.
		numBytes := int(b & 0x7f)
		if numBytes == 0 {
			err = SyntaxError{"indefinite length found (not DER)"}
			return
		}
		ret.length = 0
		for i := 0; i < numBytes; i++ {
			if offset >= len(bytes) {
				err = SyntaxError{"truncated tag or length"}
				return
			}
			b = bytes[offset]
			offset++
			if ret.length >= 1<<23 {
				// We can't shift ret.length up without
				// overflowing.
				err = StructuralError{"length too large"}
				return
			}
			ret.length <<= 8
			ret.length |= int(b)
			if ret.length == 0 {
				// DER requires that lengths be minimal.
				err = StructuralError{"superfluous leading zeros in length"}
				return
			}
		}
		// Short lengths must be encoded in short form.
		if ret.length < 0x80 {
			err = StructuralError{"non-minimal length"}
			return
		}
	}

	return
}

// invalidLength returns true iff offset + length > sliceLength, or if the
// addition would overflow.
func invalidLength(offset, length, sliceLength int) bool {
	return offset+length < offset || offset+length > sliceLength
}

type ASN1Obj struct {
	Name         string
	Tag          int
	GetInnerTags bool
	Optional     bool
}

//takes a byte array and starting offset returns the appropriate next offset
func (obj *ASN1Obj) AdvanceOffset(bytes []byte, initialOffset int) (int, error) {
	tagAndLen, offset, err := parseTagAndLength(bytes, initialOffset)
	if err != nil {
		return -1, err
	}

	if obj.Name == "Certificate" {
		if invalidLength(offset, tagAndLen.length, len(bytes)) {
			err = SyntaxError{"data truncated"}
			return -1, err
		}
	}

	if tagAndLen.tag != obj.Tag {
		if obj.Optional {
			return initialOffset, nil
		} else {
			return -1, errors.New(fmt.Sprintf("%s tag error: expected %d got %d", obj.Name, obj.Tag, tagAndLen.tag))
		}
	}

	if obj.Tag == asn1.TagSequence && obj.GetInnerTags {
		return offset, nil
	} else {
		return offset + tagAndLen.length, nil
	}
}

type MissingExtensionError struct {}
func (e MissingExtensionError) Error() string {
	return "Extension not found in cert"
}

//Returns the subject name as a string as well as the new offset for the next field
func (obj *ASN1Obj) extractFieldAndAdvanceOffset(bytes []byte, initialOffset int) (nextFieldOffset int, dataStartOffset int, dataLen int, err error) {
	nextFieldOffset = -1
	dataStartOffset = -1
	dataLen = -1

	tagAndLen, offset, err := parseTagAndLength(bytes, initialOffset)
	if err != nil {
		return
	}

	if tagAndLen.tag != obj.Tag {
		if obj.Optional {
			nextFieldOffset = initialOffset
			return
		} else {
			if obj.Name == "Extensions" && obj.Tag == 3 && tagAndLen.tag == 16 {
				err = MissingExtensionError{}
			} else {
				err = errors.New(fmt.Sprintf("%s tag error: expected %d got %d", obj.Name, obj.Tag, tagAndLen.tag))
			}
			return
		}
	}

	if obj.GetInnerTags {
		nextFieldOffset = offset
		dataStartOffset = offset
		dataLen = tagAndLen.length
	} else {
		nextFieldOffset = offset + tagAndLen.length
		dataStartOffset = offset
		dataLen = tagAndLen.length
	}
	return
}


func (obj *ASN1Obj) PublicKey(bytes []byte, initialOffset int) ([]byte, int, error) {
	if obj.Name != "SubjectPublicKeyInfo" {
		panic("Cannot call SubjectCommonName() on " + obj.Name)
	}

	nextOffset, dataOffset, dataLen, err := obj.extractFieldAndAdvanceOffset(bytes, initialOffset)
	if err != nil {
		return nil, nextOffset, err
	}

	return bytes[initialOffset:dataOffset+dataLen], nextOffset, nil
}

func (obj *ASN1Obj) SubjectCommonName(bytes []byte, initialOffset int) (*pkix.Name, []byte, int, error) {
	if obj.Name != "Subject" {
		panic("Cannot call SubjectCommonName() on " + obj.Name)
	}

	nextOffset, dataOffset, dataLen, err := obj.extractFieldAndAdvanceOffset(bytes, initialOffset)
	if err != nil {
		return nil, nil, nextOffset, err
	}

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(bytes[initialOffset:dataOffset+dataLen], &subject); err != nil {
		return nil, nil, nextOffset, err
	}

	name := &pkix.Name{}
	name.FillFromRDNSequence(&subject)

	return name, bytes[initialOffset:dataOffset+dataLen], nextOffset, nil
}

func (obj *ASN1Obj) SubjectAltName(bytes []byte, initialOffset int) ([]string, int, error) {
	if obj.Name != "Extensions" {
		panic("Cannot call SubjectAltName() on " + obj.Name)
	}

	nextOffset, dataOffset, dataLen, err := obj.extractFieldAndAdvanceOffset(bytes, initialOffset)
	if err != nil {
		return nil, nextOffset, err
	}
	if dataOffset == -1 && dataLen == -1 { //No extensions
		return nil, nextOffset, nil
	}

	ext2Obj := &ASN1Obj{
		Name:         "Extensions Part 2",
		Tag:          asn1.TagSequence,
		GetInnerTags: true,
	}

	// Get next extension
	nextOffset, dataOffset, dataLen, err = ext2Obj.extractFieldAndAdvanceOffset(bytes, dataOffset)
	if err != nil {
		return nil, nextOffset, err
	}

	for currentOffset := nextOffset; currentOffset < dataOffset+dataLen; {
		extObj := &ASN1Obj{
			Name:         "Extension",
			Tag:          asn1.TagSequence,
			GetInnerTags: false,
		}

		// Get next extension
		nextExtOffset, err := extObj.AdvanceOffset(bytes, currentOffset)
		if err != nil {
			return nil, nextOffset, err
		}

		// Parse the extension
		subjectAltNames, err := parseSAN(bytes, currentOffset, nextExtOffset-currentOffset)
		if err != nil {
			return nil, nextOffset, err
		}

		if len(subjectAltNames) > 0 {
			return subjectAltNames, nextOffset, nil
		}

		currentOffset = nextExtOffset
	}

	return nil, nextOffset, nil
}
func parseSAN(bytes []byte, dataOffset int, dataLen int) ([]string, error) {
	subjectAltNames := make([]string, 0)
	ext := pkix.Extension{}

	if rest, err := asn1.Unmarshal(bytes[dataOffset:dataOffset+dataLen], &ext); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 extension")
	}

	if ext.Id.Equal(oidExtensionSubjectAltName) {
		dnsNames, err := parseSANExtension(ext.Value)
		if err != nil {
			return nil, err
		}

		subjectAltNames = dnsNames
	}

	return subjectAltNames, nil
}

func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.Bytes); err != nil {
			return err
		}
	}

	return nil
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

func parseSANExtension(value []byte) (dnsNames []string, err error) {
	err = forEachSAN(value, func(tag int, data []byte) error {
		switch tag {
		case nameTypeDNS:
			dnsNames = append(dnsNames, string(data))
		}

		return nil
	})

	return
}


var CertObjs = []*ASN1Obj{
	{
		Name:         "Certificate",
		Tag:          asn1.TagSequence,
		GetInnerTags: true,
	},
	{
		Name:         "TBSCertificate",
		Tag:          asn1.TagSequence,
		GetInnerTags: true,
	},
	{
		Name:     "Version",
		Tag:      0, //custom tag
		Optional: true,
	},
	{
		Name: "SerialNumber",
		Tag:  asn1.TagInteger,
	},
	{
		Name:         "Signature",
		Tag:          asn1.TagSequence,
		GetInnerTags: false,
	},
	{
		Name:         "Issuer",
		Tag:          asn1.TagSequence,
		GetInnerTags: false,
	},
	{
		Name:         "Validity",
		Tag:          asn1.TagSequence,
		GetInnerTags: false,
	},
	{
		Name:         "Subject",
		Tag:          asn1.TagSequence,
		GetInnerTags: false,
	},
	{
		Name:         "SubjectPublicKeyInfo",
		Tag:          asn1.TagSequence,
		GetInnerTags: false,
	},
	{
		Name:     "IssuerUniqueId",
		Tag:      1, //custom tag
		Optional: true,
	},
	{
		Name:     "SubjectUniqueId",
		Tag:      2, //custom tag
		Optional: true,
	},
	{
		Name:         "Extensions",
		Tag:          3, //custom tag
		GetInnerTags: true,
	},
}