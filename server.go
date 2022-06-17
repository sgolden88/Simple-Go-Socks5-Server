package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

//settings
const version byte = 5 //Socks5
const method byte = 0  //Only supports 0:No auth required, and 2: User:Pass required
//TODO test authentication
const port string = ":8000"

//optional, change them if you're going to use password authentication
const user = "user"
const pass = "pass"

func main() {
	//listen and serve
	listener, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Println(err)
		return
	}
	for {
		c, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(c)
	}

}
func handleConnection(c net.Conn) {
	defer c.Close()

	reader := bufio.NewReader(c)
	//initial handshake
	v, err := reader.ReadByte()
	if v != version || err != nil {
		fmt.Println("Client does not support Socks5")
		return
	}
	cont := false
	available, err := availableMethods(reader)
	if err != nil {
		return
	}
	for _, val := range available {
		if val == method {
			cont = true
			break
		}
	}
	if !cont {
		fmt.Println("Client does not support proxy authentication method")
		return
	}
	//Handshake accepted, next does the authentication based subnegotiation
	c.Write([]byte{version, method})
	if ok, err := authenticate(reader, c); !ok || err != nil {
		c.Write([]byte{version, 1})
		return
	}

	//Read and parse request
	header := make([]byte, 4)
	if _, err = io.ReadFull(c, header); err != nil {
		fmt.Println(err)
		fmt.Println("err at header")
		return
	}
	if header[0] != version {
		fmt.Println("Client does not support Socks5")
		return
	}
	addr := ""
	var port = make([]byte, 2)
	switch header[3] {
	case 1: //ipv4
		println("type of address: ipv4")
		buf := make([]byte, 4)
		if _, err = io.ReadFull(reader, buf); err != nil {
			fmt.Println(err)
			return
		}
		for _, x := range buf {
			addr += strconv.Itoa(int(x)) + "."
		}
		addr = addr[:len(addr)-1]
	case 3: //domain
		println("type of address: domain")
		dlen, _ := reader.ReadByte()
		buf := make([]byte, dlen)
		if _, err = io.ReadFull(reader, buf); err != nil {
			fmt.Println(err)
			return
		}
		addr = string(buf)
	//TODO add ipv6 support
	default:
		println("IP Method Not Supported")
		return
	}

	if _, err = io.ReadFull(reader, port); err != nil {
		fmt.Println(err)
		return
	}

	switch header[1] {
	case 1:
		handleConRequest(c, string(addr), strconv.Itoa(int(binary.BigEndian.Uint16(port))))
	default:
		println("Cmd not supported")
		return
	}
}
func authenticate(r *bufio.Reader, c net.Conn) (bool, error) {
	if method == 0 {
		return true, nil
	}
	if v, err := r.ReadByte(); err != nil || v != version {
		return false, err
	}
	ulen, err := r.ReadByte()
	if ulen > 255 || ulen < 1 || err != nil {
		return false, err
	}
	u := make([]byte, ulen)
	_, err = io.ReadFull(r, u)
	if err != nil || string(u) != user {
		return false, err
	}
	println(string(u))
	plen, err := r.ReadByte()
	if plen > 255 || plen < 1 || err != nil {
		return false, err
	}
	p := make([]byte, plen)
	_, err = io.ReadFull(r, p)
	println(string(p))
	if err != nil || string(p) != pass {
		return false, err
	}
	//successful authentication
	c.Write([]byte{version, 0})

	return true, nil
}
func availableMethods(r *bufio.Reader) ([]byte, error) {
	numMethods, err := r.ReadByte()
	if numMethods < 1 || err != nil {
		return nil, err
	}
	methods := make([]byte, numMethods)
	if _, err = io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

func handleConRequest(c net.Conn, addr, port string) error {
	println("domain ", addr)
	println("port", port)
	//Connect with remote host
	remote, err := net.Dial("tcp", addr+":"+port)
	if err != nil {
		fmt.Println("Remote connection error:", err)
		return err
	}
	defer remote.Close()
	//most clients just ignore address data anyway
	response := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0} //version, status, reserved, address type,dummy data because client doesnt need to know the bind address
	println("Response Length", len(response))
	if _, err = c.Write(response); err != nil {
		return (err)
	}
	//Data Exchange
	ch := make(chan error, 2)
	go exchange(c, remote, ch)
	go exchange(remote, c, ch)
	for x := 0; x < 2; x++ {
		err = <-ch
		if err != nil {
			return err
		}
	}
	return nil
}
func exchange(src, dst net.Conn, c chan error) {
	_, err := io.Copy(dst, src)
	if err != nil {
		fmt.Println("Exchange error", err)
	}
}
