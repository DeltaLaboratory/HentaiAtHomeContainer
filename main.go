package main

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/schollz/progressbar/v3"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"software.sslmate.com/src/go-pkcs12"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const HathVersion = "1.6.1"

func download() {
	var fileWriter bytes.Buffer

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://repo.e-hentai.org/hath/HentaiAtHome_%s.zip", HathVersion), nil)
	res, err := http.DefaultClient.Do(req)
	defer func() {
		err := res.Body.Close()
		if err != nil {
			fmt.Printf("Failed to Download Hentai@Home : %s\n", err)
			os.Exit(10)
		}
	}()
	if err != nil {
		fmt.Printf("Failed to Download Hentai@Home : %s\n", err)
		os.Exit(10)
	}
	bar := progressbar.DefaultBytes(res.ContentLength, "Downloading Hentai@Home")
	if _, err = io.Copy(io.MultiWriter(bar, &fileWriter), res.Body); err != nil {
		fmt.Printf("Failed to Download Hentai@Home : %s\n", err)
		os.Exit(10)
	}
	file := fileWriter.Bytes()
	zipReader, _ := zip.NewReader(bytes.NewReader(file), int64(len(file)))
	f, err := zipReader.Open("HentaiAtHome.jar")
	if err != nil {
		fmt.Printf("Failed to Extract Hentai@Home : %s\n", err)
		os.Exit(15)
	}
	hathFile, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("Failed to Extract Hentai@Home : %s\n", err)
		os.Exit(15)
	}
	err = ioutil.WriteFile("/hath/hath.jar", hathFile, 0655)
	if err != nil {
		fmt.Printf("Could Not Write Hentai@Home File : %s\n", err)
		os.Exit(20)
	}
	fmt.Println("Download Completed")
	return
}

func createCredential(clientId, clientKey string) {
	if err := os.MkdirAll("/hath/data", 0644); err != nil {
		fmt.Printf("Failed to Create Credential File Directory : %s\n", err)
		os.Exit(40)
	}
	fs, err := os.OpenFile("/hath/data/client_login", os.O_CREATE|os.O_WRONLY, 644)
	if err != nil {
		fmt.Printf("Failed to Open Credential File : %s\n", err)
		os.Exit(20)
	}
	_, err = fs.WriteString(fmt.Sprintf("%s-%s", clientId, clientKey))
	if err != nil {
		fmt.Printf("Failed to Write Credential File : %s\n", err)
		os.Exit(25)
	}
}

func main() {
	if _, err := os.Stat("/hath/hath.jar"); err != nil {
		fmt.Println("Hentai@Home is Missing, Download New One...")
		download()
	}
	if os.Getenv("CLIENT_ID") == "" || os.Getenv("CLIENT_KEY") == "" {
		fmt.Println("Client ID or Client Key is not set Properly.")
		os.Exit(30)
	}
	createCredential(os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_KEY"))
	fmt.Println("Starting Hentai@Home Process...")
	process := exec.Command("java", "-jar", "/hath/hath.jar")
	if err := process.Start(); err != nil {
		fmt.Printf("An Error was Occured while Staring Hentai@Home Process : %s\n", err)
		os.Exit(35)
	}
	done := make(chan any)
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL)
	// Cert/Domain Name Provider
	go func() {
		if strings.ToLower(os.Getenv("GENERATE_CERT")) != "true" {
			return
		}
		var retry int
		fmt.Println("Creating PEM-Encoded Certificate...")
		for {
			trustStore, err := ioutil.ReadFile("/hath/data/hathcert.p12")
			if err != nil {
				retry += 15
				fmt.Printf("Could Not Read Hath Network Cert, Try After %s", strconv.Itoa(retry))
				time.Sleep(time.Second * time.Duration(retry))
				continue
			}
			privateKey, cert, ca, err := pkcs12.DecodeChain(trustStore, os.Getenv("CLIENT_KEY"))
			if err != nil {
				fmt.Printf("Could Not Decode Trust Store : %s\n", err)
				return
			}
			fmt.Printf("Certificate DN=%s\n", cert.DNSNames[0])
			fmt.Printf("Certificate SN=%s\n", cert.SerialNumber)
			fmt.Printf("Certificate Algo=%s\n", cert.PublicKeyAlgorithm)
			fmt.Printf("Certificate Expire=%s\n", cert.NotAfter.String())
			if err := os.MkdirAll("/cert", 0644); err != nil {
				fmt.Printf("Failed to Create Cert File Directory : %s\n", err)
				return
			}
			privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				fmt.Printf("Could Not Encode PrivateKey : %s\n", err)
				return
			}
			certKey := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privateKeyDER,
			})
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			caPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: ca[0].Raw,
			})
			err = ioutil.WriteFile("/cert/cert.pem", certPEM, 0644)
			if err != nil {
				fmt.Printf("Could Not Write Cert PEM : %s\n", err)
				return
			}
			err = ioutil.WriteFile("/cert/cert.key", certKey, 0644)
			if err != nil {
				fmt.Printf("Could Not Write Private Key : %s\n", err)
				return
			}
			err = ioutil.WriteFile("/cert/ca.pem", caPEM, 0644)
			if err != nil {
				fmt.Printf("Could Not Write CA PEM : %s\n", err)
				return
			}
			err = ioutil.WriteFile("/cert/host", []byte(cert.DNSNames[0]), 0644)
			if err != nil {
				fmt.Printf("Could Not Write Hentai@Home Network Host File : %s\n", err)
				return
			}
			fmt.Println("Certificate Generated!")
			return
		}
	}()
	// Shutdown Handler
	go func() {
		<-sigChannel
		fmt.Println("Shutting Down Hentai@Home...")
		if err := process.Process.Signal(syscall.SIGINT); err != nil {
			fmt.Printf("An Error was Occured while Shutting Down Hentai@Home Process : %s\n", err)
			done <- nil
			return
		}
		_ = process.Wait()
		done <- nil
		return
	}()
	go func() {
		err := process.Wait()
		fmt.Printf("Hentai@Home Process Exited : %s", err.Error())
		// done <- nil
	}()
	<-done
	return
}
