package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"strings"
)

// dnsHeader represents DNS query's header section.
// see https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
type dnsHeader struct {
	transactionId uint16
	flags         uint16
	qdCount       uint16 // the number of entries in the question section
	anCount       uint16 // the number of resource records in the answer section
	nsCount       uint16 // the number of name server resource records in the authority records section
	arCount       uint16 // the number of resource records in the additional records section
}

func headerToBytes(header dnsHeader) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, &header)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dnsQuestion represents DNS query's question section.
// see https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
type dnsQuestion struct {
	qname  []byte
	qtype  uint16
	qclass uint16
}

func questionToBytes(question dnsQuestion) ([]byte, error) {
	type s struct {
		qtype  uint16
		qclass uint16
	}
	ss := s{
		qtype:  question.qtype,
		qclass: question.qclass,
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, question.qname)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, &ss)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// encodeDnsName encodes domainName as QNAME.
//
// a domain name represented as a sequence of labels, where each label consists of a length octet followed by that
// number of octets.  The domain name terminates with the zero length octet for the null label of the root.
func encodeDnsName(domainName string) ([]byte, error) {
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

const (
	TYPE_A   = 1
	CLASS_IN = 1
)

func buildQuery(domainName string, recordType uint16) ([]byte, error) {
	name, err := encodeDnsName(domainName)
	if err != nil {
		return nil, err
	}
	id := rand.Intn(65535)
	RECURSION_DESIRED := 1 << 8

	header := dnsHeader{
		transactionId: uint16(id),
		flags:         uint16(RECURSION_DESIRED),
		qdCount:       1,
	}
	headerBytes, err := headerToBytes(header)
	if err != nil {
		return nil, err
	}

	question := dnsQuestion{
		qname:  name,
		qtype:  recordType,
		qclass: CLASS_IN,
	}
	questionBytes, err := questionToBytes(question)
	if err != nil {
		return nil, err
	}

	return append(headerBytes, questionBytes...), nil
}

func run() {
	query, err := buildQuery("www.example.com", TYPE_A)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		log.Fatal(err)
	}

	response := make([]byte, 1024)
	_, err = conn.Read(response)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	run()
	// % sudo tcpdump -ni any port 53
	// Password:
	// tcpdump: data link type PKTAP
	// tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
	// listening on any, link-type PKTAP (Apple DLT_PKTAP), snapshot length 524288 bytes
	// 22:20:17.785047 IP 192.168.0.32.60529 > 8.8.8.8.53: 62929+ A? www.example.com. (33)
	// 22:20:17.809896 IP 8.8.8.8.53 > 192.168.0.32.60529: 62929 1/0/0 A 93.184.216.34 (49)
}
