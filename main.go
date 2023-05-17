package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
)

// DNSHeader represents DNS query's header section.
// see https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
type DNSHeader struct {
	TransactionId uint16
	Flags         uint16
	QdCount       uint16 // the number of entries in the question section
	AnCount       uint16 // the number of resource records in the answer section
	NsCount       uint16 // the number of name server resource records in the authority records section
	ArCount       uint16 // the number of resource records in the additional records section
}

func (dh *DNSHeader) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("TransactionId: %d", dh.TransactionId))
	sb.WriteString(fmt.Sprintf(", Flags: %d", dh.Flags))
	sb.WriteString(fmt.Sprintf(", QdCount: %d", dh.QdCount))
	sb.WriteString(fmt.Sprintf(", AnCount: %d", dh.AnCount))
	sb.WriteString(fmt.Sprintf(", NsCount: %d", dh.NsCount))
	sb.WriteString(fmt.Sprintf(", ArCount: %d", dh.ArCount))
	return sb.String()
}

func headerToBytes(header DNSHeader) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, &header)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseHeader(reader *bytes.Reader) (*DNSHeader, error) {
	header := &DNSHeader{}
	err := binary.Read(reader, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

// DNSQuestion represents DNS query's question section.
// see https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
type DNSQuestion struct {
	Qname []byte
	subDNSQuestion
}

type subDNSQuestion struct {
	Qtype  uint16
	Qclass uint16
}

func (dq *DNSQuestion) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s", string(dq.Qname)))
	sb.WriteString(fmt.Sprintf(", type: %d", dq.Qtype))
	sb.WriteString(fmt.Sprintf(", class: %d", dq.Qclass))
	return sb.String()
}

func questionToBytes(question DNSQuestion) ([]byte, error) {
	ss := subDNSQuestion{
		Qtype:  question.Qtype,
		Qclass: question.Qclass,
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, question.Qname)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, &ss)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func parseQuestion(reader *bytes.Reader) (*DNSQuestion, error) {
	name, err := decodeName(reader)
	if err != nil {
		return nil, err
	}

	subDNSQuestion := &subDNSQuestion{}
	err = binary.Read(reader, binary.BigEndian, subDNSQuestion)
	if err != nil {
		return nil, err
	}

	return &DNSQuestion{Qname: name, subDNSQuestion: *subDNSQuestion}, nil
}

// DNSRecord represents DNS record.
// see https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
type DNSRecord struct {
	Name []byte
	SubDNSRecord
	Rdata []byte
}

type SubDNSRecord struct {
	Type     uint16
	Class    uint16
	Ttl      uint32
	RdLength uint16
}

func (dr *DNSRecord) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s", string(dr.Name)))
	sb.WriteString(fmt.Sprintf(", type: %d", dr.Type))
	sb.WriteString(fmt.Sprintf(", class: %d", dr.Class))
	sb.WriteString(fmt.Sprintf(", ttl: %d", dr.Ttl))
	sb.WriteString(fmt.Sprintf(", rdLength: %d", dr.RdLength))

	switch dr.Type {
	case TYPE_NS, TYPE_CNAME:
		sb.WriteString(fmt.Sprintf(", rdata: %s", string(dr.Rdata)))
	case TYPE_A:
		sb.WriteString(fmt.Sprintf(", rdata: %s", ip2String(dr.Rdata)))
	default:
		sb.WriteString(fmt.Sprintf(", rdata: %x", dr.Rdata))
	}

	return sb.String()
}

func parseRecord(reader *bytes.Reader) (*DNSRecord, error) {
	name, err := decodeName(reader)
	if err != nil {
		return nil, err
	}

	subDNSRecord := &SubDNSRecord{}
	err = binary.Read(reader, binary.BigEndian, subDNSRecord)
	if err != nil {
		return nil, err
	}

	var data []byte
	switch subDNSRecord.Type {
	case TYPE_NS, TYPE_CNAME:
		// the NS record type. This record type says “hey, I don’t have the answer, but this other server does, ask them instead”.
		data, err = decodeName(reader)
		if err != nil {
			return nil, err
		}
	default:
		data = make([]byte, subDNSRecord.RdLength)
		_, err = reader.Read(data)
		if err != nil {
			return nil, err
		}
	}

	return &DNSRecord{
		Name:         name,
		SubDNSRecord: *subDNSRecord,
		Rdata:        data,
	}, nil
}

func ip2String(ip []byte) string {
	ips := make([]string, len(ip))
	for i, v := range ip {
		ips[i] = strconv.Itoa(int(v))
	}
	return strings.Join(ips, ".")
}

// encodeDNSName encodes domainName as QNAME.
//
// a domain name represented as a sequence of labels, where each label consists of a length octet followed by that
// number of octets.  The domain name terminates with the zero length octet for the null label of the root.
func encodeDNSName(domainName string) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, part := range strings.Split(domainName, ".") {
		if err := binary.Write(buf, binary.BigEndian, uint8(len(part))); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, []byte(part)); err != nil {
			return nil, err
		}
	}
	if err := binary.Write(buf, binary.BigEndian, uint8(0)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeName(reader *bytes.Reader) ([]byte, error) {
	var parts []string

	for {
		length, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if length == 0 {
			break
		}

		// see https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
		if length&0b11000000 == 0b11000000 {
			compressedParts, err := decodeCompressedName(length, reader)
			if err != nil {
				return nil, err
			}
			parts = append(parts, string(compressedParts))
			break
		}

		part := make([]byte, length)
		_, err = reader.Read(part)
		if err != nil {
			return nil, err
		}

		parts = append(parts, string(part))
	}

	return []byte(strings.Join(parts, ".")), nil
}

func decodeCompressedName(length uint8, reader *bytes.Reader) ([]byte, error) {
	next, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	pointer := int(length&0x3F)<<8 | int(next)
	currentPos := reader.Size() - int64(reader.Len())
	reader.Seek(int64(pointer), 0)

	compressedPart, err := decodeName(reader)
	if err != nil {
		return nil, err
	}

	// Return the pointer to the original position
	reader.Seek(currentPos, 0)

	return compressedPart, nil
}

// DNSPacket represents DNS packet.
// see https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
type DNSPacket struct {
	Header      *DNSHeader
	Questions   []*DNSQuestion
	Answers     []*DNSRecord
	Authorities []*DNSRecord
	Additionals []*DNSRecord
}

func parsePacket(data []byte) (*DNSPacket, error) {
	reader := bytes.NewReader(data)

	header, err := parseHeader(reader)
	if err != nil {
		return nil, err
	}

	questions := make([]*DNSQuestion, header.QdCount)
	for i := range questions {
		question, err := parseQuestion(reader)
		if err != nil {
			return nil, err
		}
		questions[i] = question
	}

	answers := make([]*DNSRecord, header.AnCount)
	for i := range answers {
		answer, err := parseRecord(reader)
		if err != nil {
			return nil, err
		}
		answers[i] = answer
	}

	authorities := make([]*DNSRecord, header.NsCount)
	for i := range authorities {
		authority, err := parseRecord(reader)
		if err != nil {
			return nil, err
		}
		authorities[i] = authority
	}

	additionals := make([]*DNSRecord, header.ArCount)
	for i := range additionals {
		additional, err := parseRecord(reader)
		if err != nil {
			return nil, err
		}
		additionals[i] = additional
	}

	return &DNSPacket{
		Header:      header,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}, nil
}

const (
	TYPE_A     uint16 = 1
	TYPE_NS    uint16 = 2
	TYPE_CNAME uint16 = 5

	CLASS_IN = 1
)

func buildQuery(domainName string, recordType uint16) ([]byte, error) {
	name, err := encodeDNSName(domainName)
	if err != nil {
		return nil, err
	}
	id := rand.Intn(65535)

	header := DNSHeader{
		TransactionId: uint16(id),
		Flags:         0,
		QdCount:       1,
	}
	headerBytes, err := headerToBytes(header)
	if err != nil {
		return nil, err
	}

	subDNSQuestion := subDNSQuestion{
		Qtype:  recordType,
		Qclass: CLASS_IN,
	}
	question := DNSQuestion{
		Qname:          name,
		subDNSQuestion: subDNSQuestion,
	}
	questionBytes, err := questionToBytes(question)
	if err != nil {
		return nil, err
	}

	return append(headerBytes, questionBytes...), nil
}

func sendQuery(ipAddress, domainName string, recordType uint16) (*DNSPacket, error) {
	query, err := buildQuery(domainName, recordType)
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("udp", ipAddress+":53")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		return nil, err
	}

	response := make([]byte, 1024)
	_, err = conn.Read(response)
	if err != nil {
		return nil, err
	}

	return parsePacket(response)
}

func getAnswer(packet *DNSPacket) []byte {
	for _, ans := range packet.Answers {
		// return the first A record in the Answer section
		if ans.Type == TYPE_A {
			return ans.Rdata
		}
	}

	return nil
}

func getNameServerIP(packet *DNSPacket) []byte {
	for _, add := range packet.Additionals {
		// return the first A record in the Additional section
		if add.Type == TYPE_A {
			return add.Rdata
		}
	}

	return nil
}

func getNameServer(packet *DNSPacket) string {
	for _, aut := range packet.Authorities {
		// return the first NS record in the Authority section
		if aut.Type == TYPE_NS {
			return string(aut.Rdata)
		}
	}

	return ""
}

func getCanonical(packet *DNSPacket) string {
	for _, ans := range packet.Answers {
		if ans.Type == TYPE_CNAME {
			return string(ans.Rdata)
		}
	}

	return ""
}

func resolve(domainName string, recordType uint16) (string, error) {
	// Real DNS resolvers actually do hardcode the IP addresses of the root nameservers.
	// This is because if you’re implementing DNS, you have to start somewhere
	// – if you’re implementing DNS, you can’t use DNS to look up the IP address.
	nameServer := "198.41.0.4"
	for {
		fmt.Printf("Querying %s for %s\n", nameServer, domainName)
		packet, err := sendQuery(nameServer, domainName, recordType)
		if err != nil {
			return "", err
		}

		ip := getAnswer(packet)
		if ip != nil {
			return ip2String(ip), nil
		}

		nsIP := getNameServerIP(packet)
		if nsIP != nil {
			nameServer = ip2String(nsIP)
			continue
		}

		nsDomain := getNameServer(packet)
		if nsDomain != "" {
			nameServer, err = resolve(nsDomain, TYPE_A)
			if err != nil {
				return "", err
			}
			continue
		}

		canonical := getCanonical(packet)
		if canonical != "" {
			domainName = canonical
			continue
		}

		return "", fmt.Errorf("something went wrong")
	}
}

func run(domainName string) {
	packet, err := sendQuery("198.41.0.4", domainName, TYPE_A)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Answers ===")
	for _, ans := range packet.Answers {
		fmt.Println(ans)
	}
	fmt.Println("Authorities ===")
	for _, aut := range packet.Authorities {
		fmt.Println(aut)
	}
	fmt.Println("Additionals ===")
	for _, add := range packet.Additionals {
		fmt.Println(add)
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <domainName>\n", os.Args[0])
		return
	}

	ip, err := resolve(os.Args[1], TYPE_A)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ip)
}
