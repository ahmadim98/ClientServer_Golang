package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"bufio"
	"os"
)


func handleConnClient(key []byte,conn net.Conn) {
	block, cipherErr := aes.NewCipher(key)
	if cipherErr != nil {
		fmt.Errorf("Can't create cipher:", cipherErr)

		return
	}

	iv := make([]byte, aes.BlockSize)
	if _, randReadErr := io.ReadFull(rand.Reader, iv); randReadErr != nil {
		fmt.Errorf("Can't build random iv", randReadErr)

		return
	}

	_, ivWriteErr := conn.Write(iv)
	if ivWriteErr != nil {
		fmt.Errorf("Can't send IV:", ivWriteErr)

		return

	} else {
		fmt.Println("IV Sent:", iv)
	}

	//from here the process of writing starts !!
	stream := cipher.NewCFBEncrypter(block, iv)

	//this is part for receiving the command from shell
	input := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("Shell > ")
		input.Scan()
		if input.Text() == "exit" {
			conn.Close()
			break
		}

		encrypted := make([]byte,len(input.Text()))//here after the encryption !
		decrypted := []byte(input.Text())

		stream.XORKeyStream(encrypted, decrypted)

		_, writeErr := conn.Write(encrypted)

		if writeErr != nil {
			fmt.Println("Write failed:", writeErr)
			return
		}

		//this part is about receiving the response from the server side
		buf := make([]byte, 4096)//the buffer size here to receive the response from the server is 4kb
		for {
			rLen, rErr := conn.Read(buf)
			if rErr == nil {
				stream.XORKeyStream(buf[:rLen], buf[:rLen])
				fmt.Println(string(buf[:rLen]))// here it's going to print the output of the client !
				break
			}

			if rErr == io.EOF {
				stream.XORKeyStream(buf[:rLen], buf[:rLen])

				fmt.Println("Data:", string(buf[:rLen]), rLen, "EOF -")

				break
			}

			fmt.Errorf("Error while reading from",conn.RemoteAddr(),":",rErr,)
			break
		}

	}
}

func main() {
	//this is the encryption key , it should be the same for both client and server !
	key := []byte("example key 1234")
	conn, err := net.Dial("tcp", "127.0.0.1:9080")

	if err != nil {
		panic(err)
	}

	handleConnClient(key, conn)
}
