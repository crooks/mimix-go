// vim: tabstop=2 shiftwidth=2

// Mimis - A Mixmaster-like packet encoder
package main

import (
		"crypto/rand"
		"crypto/sha256"
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
	nextHop string // 80 Bytes
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
	payloadLength uint16 // 2 Bytes
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

// ExitEncode takes an exit type struct and outputs it as a byte slice.  This
// becomes a component of the inner header.  It contains loads of padding as
// the output needs to correspond exactly with the intermediate type component;
// The two being interchangable within the inner header.

/* Header Format:-
Description										Bytes				Position
Chunk number                 1 byte       0
Number of chunks             1 byte       1
Message ID                  16 bytes      2-17
Initialization vector       16 bytes      18-33
Exit type                    1 byte       34
Payload Length               2 bytes      35-36
Payload digest              32 bytes      37-68
Padding                    187 bytes      69-255
*/
func ExitEncode(e exit) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(e.chunknum))
	buf.WriteByte(byte(e.numchunks))
	buf.Write(e.messageid)
	buf.Write(e.iv)
	buf.WriteByte(byte(e.exitType))
	buf.Write(encode_uint16(e.payloadLength))
	buf.Write(e.payloadHash)
	buf.Write(randbytes(187))
	if buf.Len() != 256 {
		fmt.Printf("Error: Incorrect exit length: %d\n", buf.Len())
	}
	return buf.Bytes()
}

// ExitDecode reverses the action of ExitEncode.  The output is an exit-type struct
// containing the exit header components.
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
	e.payloadLength = decode_uint16(b[35:37])
	e.payloadHash = b[37:69]
	return e
}

// IntermediateEncode takes an intermediate type struct and outputs it as a
// byte slice.

/* Header Format:-
Description										Bytes				Position
9 Initialization vectors      144 bytes   0-143
Next address                   80 bytes   144-223
Anti-tag digest                32 bytes   224-255
*/
func IntermediateEncode(i intermediate) []byte {
	if len(i.ivs) != 144 {
		fmt.Println("Error: Incorrect IV Bytes")
	}
	buf := new(bytes.Buffer)
	buf.Write(i.ivs)
	buf.WriteString(padstring(i.nextHop, 80))
	buf.Write(i.antiTag)
	if buf.Len() != 256 {
		fmt.Println("Error: Incorrect intermediate length")
	}
	return buf.Bytes()
}

// IntermediateDecode reverses the actions of IntermedateEncode.  It outputs an
// intermediate type struct containing the associated header components.
func IntermediateDecode(b []byte) intermediate {
	if len(b) != 256 {
		fmt.Println("Error: Incorrect byte count to expand intermediate")
	}
	i := intermediate{}
	i.ivs = b[:144]
	i.nextHop = strings.TrimRight(string(b[144:224]), "\x00")
	return i
}

// InnerEncode compiles the mimix inner header that will become the encrypted
// element of the complete 1024 byte header.

/* Header Format:-
Description										Bytes				Position
Packet ID                     16 bytes    0-15
AES key                       32 bytes    16-47
Packet type identifier         1 byte     48    (0 = intermediate, 1 = exit)
Packet Info                  256 bytes    49-304
Timestamp                      2 bytes    321-322
Padding                       13 bytes    323-335
Message digest                64 bytes    336-383
*/
func InnerEncode(i inner) []byte {
	if len(i.aesKey) != 32 {
		fmt.Println("Incorrect inner aeskey length")
	}
	if i.packetType != 0  && i.packetType != 1 {
		fmt.Println("Invalid packet type")
	}
	if len(i.packetInfo) != 256 {
		fmt.Println("Invalid Packet Info length")
	}
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

// OuterEncode takes the inner header (as a byte slice) and encrypts it using
// an internally-generated AES256 key and IV.  The key is then RSA encrypted
// using the Public Key for the next-hop recipient and the AES key is
// discarded.  The IV is retained unencrypted within the output packet.

/* Header Format:-
Description										Bytes				Position
Public KeyID									16 bytes		0-15
Length of RSA-encrypted data   2 bytes		16-17
RSA-encrypted session key    512 bytes		18-530
Initialization vector         16 bytes		530-545
Encrypted header part        384 bytes 		546-929
Padding                       30 bytes		930-959
Message digest                64 bytes		960-1023
*/
func OuterEncode (innerHeader []byte) []byte {
	buf := new(bytes.Buffer)
	// Write a fake keyid until we implement proper RSA key management
	publicKeyid := []byte("0123456789012345")
	buf.Write(publicKeyid)
	// This AES key and IV are used (and only used) to encrypt the inner packet
	// header.
	aeskey := randbytes(32)
	aesiv := randbytes(16)
	// Encrypt the inner block using AES256
	aesEncrypted := make([]byte, 384)
	EncryptAESCFB(aesEncrypted, innerHeader, aeskey, aesiv)
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

// OuterDecode, unlike other decode functions returns a byte array instead of a
// struct.  The sole output of the function is the decrypted inner header.  The
// other components of the header are only required within this function to
// perform the integrity check and decryption.
func OuterDecode (outer []byte) (plain []byte) {
	if len(outer) != 1024 {
		fmt.Println("Error: Incorrect byte count to decode inner header")
	}
	check := sha512.New()
	check.Write(outer[:960])
	hash := outer[960:]
	if ! bytes.Equal(check.Sum(nil), hash) {
		fmt.Println("Error: Outer checksum failed")
	}
	//The public key is required in order to know which RSA key to use for
	//decryption.  At the moment this isn't implemented.
	//publicKeyid := outer[:16]
	rsaDataLen := decode_uint16(outer[16:18])
	fmt.Println("lenRSA:", rsaDataLen)
	keyend := 18 + rsaDataLen
	rsaData := outer[18:keyend]
	aeskey := decrypt(rsaData)
	aesiv := outer[530:546]
	// Need a slice of the correct size to receive the decrypted inner
	plain = make([]byte, 384)
	DecryptAESCFB(plain, outer[546:930], aeskey, aesiv)
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

func EncryptPayload(msgPlain, aeskey, aesiv []byte) ([]byte, uint16) {
	msgEnc := make([]byte, len(msgPlain))
	EncryptAESCFB(msgEnc, msgPlain, aeskey, aesiv)
	buf := new(bytes.Buffer)
	buf.Write(msgEnc)
	msgLen := len(msgEnc)
	if msgLen < 10240 {
		buf.Write(randbytes(10240 - msgLen))
	}
	return buf.Bytes(), uint16(msgLen)
}


func EncryptMessage(msg []byte) (packet []byte) {
	// Define message ID early as it remains consistent across all message
	// chunks.
	messageid := randbytes(16)
	packet = make([]byte, 0, 20480)
	var packetType uint8 = 1
	var payload []byte
	var payloadLen uint16
	var actualLength, expectedLength int
	for h := 0; h < 2; h++ {
		var innerHeader = inner{}
		innerHeader.aesKey = randbytes(32)
		innerHeader.packetType = packetType
		if packetType == 1 {
			var packetInfo = exit{}
			packetInfo.chunknum = 1
			packetInfo.numchunks = 1
			packetInfo.messageid = messageid
			packetInfo.iv = randbytes(16)
			packetInfo.exitType = 0
			payload, payloadLen = EncryptPayload(msg, innerHeader.aesKey, packetInfo.iv)
			packetInfo.payloadLength = payloadLen
			if payloadLen != uint16(len(msg)) {
				fmt.Println("Encrypted payload length != plain message length")
			}
			hash := sha256.New()
			hash.Write(msg)
			packetInfo.payloadHash = hash.Sum(nil)
			innerHeader.packetInfo = ExitEncode(packetInfo)
			// There is only ever a single exit header.  All proceeding headers need to
			// be Type 0 (Intermediate).
			packetType = 0
		} else if packetType == 0 {
			var packetInfo = intermediate{}
			packetInfo.ivs = randbytes(144)
			// The next two are currently fake.
			packetInfo.nextHop = "http://foo.bar.org"
			packetInfo.antiTag = randbytes(32)
			payloadiv := packetInfo.ivs[128:144]
			payload, payloadLen = EncryptPayload(payload, innerHeader.aesKey, payloadiv)
			if payloadLen != 10240 {
				fmt.Println("Encrypted payload length != 10240")
			}
			innerHeader.packetInfo = IntermediateEncode(packetInfo)
			// At this point, the new intermediate header it built (but not yet
			// inserted into the packet).  All the other existing headers now need
			// to be wrapped with a layer of encryption.
			for h2 := 0; h2 < h; h2++ {
				// Each 16 byte IV is extracted from the randomly generated 144 Byte
				// Packet Info IVs.
				ivStart := h2 * 16
				ivEnd := ivStart + 16
				iv := packetInfo.ivs[ivStart:ivEnd]
				headerStart := h2 * 1024
				headerEnd := headerStart + 1024
				// Make a new slice referencing the correct Bytes within the packet
				headerSlice := packet[headerStart:headerEnd]
				// Another slice is required to accommodate the encrypted header,
				// prior to copying it into the packet.
				headerEnc := make([]byte, len(headerSlice))
				EncryptAESCFB(headerEnc, headerSlice, innerHeader.aesKey, iv)
				copy(headerEnc, headerSlice)
			}
		}
		// Write the new header into the compiled packet.
		packet = append(OuterEncode(InnerEncode(innerHeader)), packet...)
		expectedLength = (h + 1) * 1024
		actualLength = len(packet)
		if actualLength != expectedLength {
			fmt.Printf("Incorrect packet length. Expected %d, got %d",
				expectedLength, actualLength)
		}
	}
	// The header component of the packet must always be 10240 Bytes (10 headers
	// of 1024 Bytes each).  We've already validated the packet length as being
	// the correct multiple of the number of headers generated so it's safe here
	// to just append random bytes.
	padding := 10240 - len(packet)
	packet = append(packet, randbytes(padding)...)
	// Finally, append the payload which is already padded to 10240 Bytes.
	packet = append(packet, payload...)
	if len(packet) != 20480 {
		fmt.Println("Incorrect total packet length.")
	}
	return
}


func main() {
	msg := []byte("This is a test message")
	fmt.Println(len(EncryptMessage(msg)))
}
