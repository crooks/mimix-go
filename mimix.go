// vim: tabstop=2 shiftwidth=2

// A mimix packet encoder/decoder
package main

import (
		"crypto/rand"
		//"crypto/sha256"
		"crypto/sha512"
		"fmt"
		"encoding/binary"
		"bytes"
		"strings"
		"time"
)

// intermediate is one type of PacketInfo (the other being exit). Each mimix
// message can contain 0-9 intermediate headers.  Nine IVs are required to
// decode the other headers (and payload) and they are concatenated into the
// ivs slice.
type intermediate struct {
	ivs []byte // 144 Bytes (9 * 16)
	next_hop string // 80 Bytes
	antiTag []byte // 32 Bytes (SHA256)
	// Total size: 256 Bytes
}

// exit is the alternative type of Packet info to intermediate.  It may only
// occur once per encoded message and contains the info required to decrypt
// and verify the payload.
type exit struct {
	chunknum uint8 // Byte
	numchunks uint8 // Byte
	messageid []byte // 16 Bytes
	iv []byte // 16 Bytes
	exitType uint8 // Byte
	payloadHash []byte // 32 Bytes (SHA256)
}

// inner contains secret info relating to the payload and other packets.  It
// also contains one of the intermediate or exit structs in byte format.
type inner struct {
	packetid []byte // 16 Bytes
	aesKey []byte // 32 Bytes
	packetType uint8 // Byte
	packetInfo []byte // 256 Bytes (exit or inner)
	timestamp uint32 // 4 Bytes
}

// outer contains the encrypted inner struct (in byte format) along with the
// info required to enable the recipient to decrypt it.  An AES key is
// encrypted with the recipient's Public RSA key and the corresponding IV is
// passed in plain text.  This key/iv conbination is required to decrypt the
// inner component.
type outer struct {
	publicKeyid []byte //16 Bytes
	inner []byte // 384 Bytes
}

func ExitEncode(e exit) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(e.chunknum))
	buf.WriteByte(byte(e.numchunks))
	buf.Write(e.messageid)
	buf.Write(e.iv)
	buf.WriteByte(byte(e.exitType))
	buf.Write(e.payloadHash)
	buf.Write(randbytes(189))
	if buf.Len() != 256 {
		fmt.Println("Error: Incorrect exit length")
	}
	return buf.Bytes()
}

func ExitDecode(b []byte) exit {
	if len(b) != 256 {
		fmt.Println("Error: Incorrect byte count to expand exit")
	}
	e := exit{}
	e.chunknum = b[0]
	e.numchunks = b[1]
	e.messageid = b[2:18]
	e.iv = b[18:34]
	e.exitType = b[34]
	e.payloadHash = b[35:67]
	return e
}


func IntermediateEncode(i intermediate) []byte {
	if len(i.ivs) != 144 {
		fmt.Println("Error: Incorrect IV Bytes")
	}
	buf := new(bytes.Buffer)
	buf.Write(i.ivs)
	buf.WriteString(padstring(i.next_hop, 80))
	buf.Write(i.antiTag)
	if buf.Len() != 256 {
		fmt.Println("Error: Incorrect intermediate length")
	}
	return buf.Bytes()
}

func IntermediateDecode(b []byte) intermediate {
	if len(b) != 256 {
		fmt.Println("Error: Incorrect byte count to expand intermediate")
	}
	i := intermediate{}
	i.ivs = b[:144]
	i.next_hop = strings.TrimRight(string(b[144:224]), "\x00")
	return i
}

func InnerEncode(i inner) []byte {
	buf := new(bytes.Buffer)
	buf.Write(randbytes(16)) // Packet ID
	buf.Write(i.aesKey)
	buf.WriteByte(i.packetType)
	buf.Write(i.packetInfo)
	// Timestamp is written without consideration for what's passed in
	// inner.timestamp.
	buf.Write(encode_uint32(epochDays()))
	buf.Write(randbytes(11))
	h := sha512.New()
	h.Write(buf.Bytes())
	buf.Write(h.Sum(nil))
	if buf.Len() != 384 {
		fmt.Println("Error: Incorrect inner length")
	}
	return buf.Bytes()
}

func InnerDecode(b []byte) (i inner) {
	if len(b) != 384 {
		fmt.Println("Error: Incorrect byte count to expand inner")
	}
	check := sha512.New()
	check.Write(b[:320])
	hash := b[320:]
	if ! bytes.Equal(check.Sum(nil), hash) {
		fmt.Println("Error: Inner checksum failed")
	}
	i.packetid = b[:16]
	i.aesKey = b[16:48]
	i.packetType = b[48]
	i.packetInfo = b[49:305]
	i.timestamp = decode_uint32(b[305:309])
	// 11 Bytes padding from 309 to 320
	return
}

func OuterEncode (o outer) []byte {
	buf := new(bytes.Buffer)
	buf.Write(o.publicKeyid)
	// This AES key and IV are used (and only used) to encrypt the inner packet
	// header.
	aeskey := randbytes(32)
	aesiv := randbytes(16)
	// Encrypt the inner block using AES256
	aesEncrypted := make([]byte, len(o.inner))
	EncryptAESCFB(aesEncrypted, o.inner, aeskey, aesiv)
	// Encrypt the AES key with RSA(OAEP)
	rsaData := encrypt(aeskey)
	rsaDataLen := len(rsaData)
	buf.Write(encode_uint16(uint16(rsaDataLen)))
	buf.Write(rsaData)
	// Pad the RSA data to 512 Bytes. This provides sufficient space for a 32 bit
	// AES key encrypted with a 4096 bit RSA Key.  In such an instance, there
	// will be zero padding.
	if rsaDataLen < 512 {
		buf.Write(randbytes(512 - rsaDataLen))
	} else if rsaDataLen > 512 {
		fmt.Println("Error: RSA data size exceeds packet specification")
	}
	buf.Write(aesiv)
	buf.Write(aesEncrypted)
	buf.Write(randbytes(30))
	h := sha512.New()
	h.Write(buf.Bytes())
	buf.Write(h.Sum(nil))
	if buf.Len() != 1024 {
		fmt.Println("Error: Incorrect outer length:", buf.Len())
	}
	return buf.Bytes()
}

func OuterDecode (b []byte) (o outer) {
	if len(b) != 1024 {
		fmt.Println("Error: Incorrect byte count to expand outer")
	}
	check := sha512.New()
	check.Write(b[:960])
	hash := b[960:]
	if ! bytes.Equal(check.Sum(nil), hash) {
		fmt.Println("Error: Outer checksum failed")
	}
	o.publicKeyid = b[:16]
	rsaDataLen := decode_uint16(b[16:18])
	fmt.Println("lenRSA:", rsaDataLen)
	keyend := 18 + rsaDataLen
	rsaData := b[18:keyend]
	aeskey := decrypt(rsaData)
	aesiv := b[530:546]
	// Need a slice of the correct size to receive the decrypted inner
	plain := make([]byte, 384)
	DecryptAESCFB(plain, b[546:930], aeskey, aesiv)
	o.inner = plain
	return
}

func randbytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error:", err)
	}
  return b
}

func padstring(s string, l int) string {
	slen := len(s)
	if slen > l {
		fmt.Println("Error: String exceeds pad-to length")
	}
	return s + strings.Repeat("\x00", l - slen)
}

func epochDays() uint32 {
	return uint32((time.Now().UTC().Unix()) / 86400)
}

func encode_uint16(n uint16) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, n)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return buf.Bytes()
}

func decode_uint16(b []byte) (i uint16) {
	buf := bytes.NewReader(b)
	err := binary.Read(buf, binary.LittleEndian, &i)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return
}

func encode_uint32(n uint32) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, n)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return buf.Bytes()
}

func decode_uint32(b []byte) (i uint32) {
	buf := bytes.NewReader(b)
	err := binary.Read(buf, binary.LittleEndian, &i)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return
}

func main() {
	/*
	var i = intermediate{}
	i.ivs = randbytes(144)
	i.next_hop = "http://foo.bar.org"
	i.antiTag = randbytes(32)
	encoded := IntermediateEncode(i)
	decoded := IntermediateDecode(encoded)
	*/

	var e = exit{}
	e.chunknum = 100
	e.numchunks = 1
	e.messageid = randbytes(16)
	e.iv = randbytes(16)
	e.exitType = 0
	e.payloadHash = randbytes(32)

	var in = inner{}
	in.aesKey = randbytes(32)
	in.packetType = 1
	in.packetInfo = ExitEncode(e) // Insert Exit headers

	var out = outer{}
	out.publicKeyid = []byte("0123456789012345")
	out.inner = InnerEncode(in) // Insert Inner
	encout := OuterEncode(out)
	newout := OuterDecode(encout)
	newin := InnerDecode(newout.inner)
	if bytes.Equal(in.aesKey, newin.aesKey) {
		fmt.Println("Match")
	} else {
		fmt.Println("Broken")
	}
	newe := ExitDecode(newin.packetInfo)
	fmt.Println(newe.chunknum)
}
