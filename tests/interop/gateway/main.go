// Independent test-only SSH implementation. Binds loopback, accepts public fixture
// credentials, and never starts a host shell or executes commands from clients.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	mode := flag.String("mode", "none", "fixture authentication mode")
	keyPath := flag.String("key", "", "public test host private key")
	pubPath := flag.String("authorized-key", "", "public test client key")
	flag.Parse()
	keyBytes, err := os.ReadFile(*keyPath)
	if err != nil {
		os.Exit(2)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		os.Exit(2)
	}
	pubBytes, err := os.ReadFile(*pubPath)
	if err != nil {
		os.Exit(2)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		os.Exit(2)
	}
	password := func(_ ssh.ConnMetadata, value []byte) (*ssh.Permissions, error) {
		if string(value) == "cloudssh-public-test-password" {
			return nil, nil
		}
		return nil, io.EOF
	}
	config := &ssh.ServerConfig{}
	switch *mode {
	case "none":
		config.NoClientAuth = true
	case "password":
		config.PasswordCallback = password
	case "publickey-password":
		config.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(pub.Marshal(), key.Marshal()) {
				return nil, io.EOF
			}
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{PasswordCallback: password}}
		}
	case "otp":
		config.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge("OTP", "Public test challenge", []string{"OTP:"}, []bool{false})
			if err == nil && len(answers) == 1 && answers[0] == "123456" {
				return nil, nil
			}
			return nil, io.EOF
		}
	default:
		os.Exit(2)
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	defer listener.Close()
	// Only a port is exposed to the runner; never log usernames, keys, or responses.
	json.NewEncoder(os.Stdout).Encode(map[string]int{"port": listener.Addr().(*net.TCPAddr).Port})
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go serve(connection, config)
	}
}

func serve(connection net.Conn, config *ssh.ServerConfig) {
	defer connection.Close()
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			incoming.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		channel, requests, err := incoming.Accept()
		if err != nil {
			return
		}
		go func(channel ssh.Channel, requests <-chan *ssh.Request) {
			defer channel.Close()
			for request := range requests {
				switch request.Type {
				case "pty-req", "env", "window-change":
					request.Reply(true, nil)
				case "shell":
					request.Reply(true, nil)
					channel.Write([]byte("CLOUDSSH_GATEWAY_READY\r\n"))
				case "exec":
					request.Reply(true, nil)
					channel.Write([]byte("CLOUDSSH_GATEWAY_EXEC_OK"))
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				default:
					request.Reply(false, nil)
				}
			}
		}(channel, requests)
	}
}
