package tlsutils

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"syscall"
	"time"
)



// GetActualCipherSuites - starts a dummy server and uses ClientHelloInfo to return the actual supported ciphers
// Can be used to remove vulnerable ciphers, such as 49170 (TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA) and 10 (TLS_RSA_WITH_3DES_EDE_CBC_SHA)
func GetActualCipherSuites(certAndCaPath, keyPath string) ([]uint16, error) {
	actualCipherSuites := make([]uint16, 0)

	cipherChan := make(chan uint16, 0)
	doneChan := make(chan bool, 1)
	// 49170 - TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	// 10 - TLS_RSA_WITH_3DES_EDE_CBC_SHA
	vulnerableCipherSuites := []uint16{49170, 10}
	port, err := ephemeralPort()
	if err != nil {
		return nil, err
	}
	l := startDummyServer(port, certAndCaPath, keyPath, cipherChan, doneChan)
	defer l.Close()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	go client.Get(fmt.Sprintf("https://localhost:%d/dummy", port))

	loop:
	for {
		select {
		case v := <-cipherChan:
				if !contains(vulnerableCipherSuites, v) {
					actualCipherSuites = append(actualCipherSuites, v)
				}
		case <-doneChan:
			break loop
		}
	}

	return actualCipherSuites, nil
}

func getCiphersChannel(ciphers chan uint16, doneChan chan bool) func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
		for _, suite := range helloInfo.CipherSuites {
				ciphers <- suite
		}
		doneChan <- true
		return nil, nil
	}
}

// UTILS
func contains(s []uint16, e uint16) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func startDummyServer(port int, certAndCaPath, keyPath string, ciphers chan uint16, doneChan chan bool) *http.Server {
	serverTlsConfig := &tls.Config{
		GetCertificate: getCiphersChannel(ciphers, doneChan),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/dummy/",
		func(w http.ResponseWriter, r *http.Request) {
		},
	)
	addr := fmt.Sprintf(":%v", port)
	srv := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: serverTlsConfig,
	}
	go srv.ListenAndServeTLS(certAndCaPath, keyPath)
	time.Sleep(100 * time.Millisecond) // allow the server to start
	return srv
}

func ephemeralPort() (int, error) {
	fd, err := syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_STREAM,
		syscall.IPPROTO_TCP,
	)
	if err != nil {
		return -1, errors.New(fmt.Sprintf("Failed to obtain socket. Error: %v", err))
	}

	defer syscall.Close(fd)

	err = syscall.Bind(
		fd,
		&syscall.SockaddrInet4{
			Port: 0,
			Addr: [4]byte{0, 0, 0, 0},
		},
	)
	if err != nil {
		return -1, errors.New(fmt.Sprintf("Failed to bind socket. Error: %v", err))
	}

	var sockaddr syscall.Sockaddr
	sockaddr, err = syscall.Getsockname(fd)
	if err != nil {
		return -1, errors.New(fmt.Sprintf("Failed to Getsockname() for fd %v. Error: %v", fd, err))
	}

	sockaddr4, ok := sockaddr.(*syscall.SockaddrInet4)
	if !ok {
		return -1, errors.New(fmt.Sprintf("Expected *syscall.SockaddrInet4 from Getsockname(), but got %#v", sockaddr))
	}

	return sockaddr4.Port, nil
}
