package main

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

const LauncherVersion = "0.0.6-dev"

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("Task", "Main").Msgf("Hentai@Home Container Version %s", LauncherVersion)
	log.Info().Str("Task", "Main").Msgf("Hentai@Home Client Version %s", HathVersion)
	if _, err := os.Stat("/hath/hath.jar"); err != nil {
		log.Warn().Str("Task", "Main").Msg("Hentai@Home is Missing, Download New One...")
		download()
	}
	if os.Getenv("CLIENT_ID") == "" || os.Getenv("CLIENT_KEY") == "" {
		log.Fatal().Msg("Client ID or Client Key is not set Properly.")
		os.Exit(30)
	}
	createCredential(os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_KEY"))
	log.Info().Str("Task", "Main").Msgf("Starting Hentai@Home Process...")
	process := exec.Command("java", "-jar", "/hath/hath.jar")
	if os.Getenv("WAIT_BEFORE_START") != "" {
		wait, err := strconv.Atoi(os.Getenv("WAIT_BEFORE_START"))
		if err != nil {
			log.Fatal().Str("Task", "Main").Msgf("Cannot Parse WAIT_BEFORE_START : %s", wait)
			os.Exit(50)
		}
		log.Info().Str("Task", "Main").Msgf("Wait %ss Before Starting...", os.Getenv("WAIT_BEFORE_START"))
		time.Sleep(time.Second * time.Duration(wait))
		log.Info().Str("Task", "Main").Msgf("Done.", os.Getenv("WAIT_BEFORE_START"))
	}
	if err := process.Start(); err != nil {
		log.Fatal().Str("Task", "Main").Msgf("An Error was Occurred while Staring Hentai@Home Process : %s", err)
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
		log.Info().Str("Task", "Cert Generating").Msg("Creating PEM-Encoded Certificate...")
		for {
			trustStore, err := ioutil.ReadFile("/hath/data/hathcert.p12")
			if err != nil {
				retry += 15
				log.Warn().Str("Task", "Cert Generating").Msgf("Could Not Read Hath Network Cert, Try After %s", strconv.Itoa(retry))
				time.Sleep(time.Second * time.Duration(retry))
				continue
			}
			privateKey, cert, ca, err := pkcs12.DecodeChain(trustStore, os.Getenv("CLIENT_KEY"))
			if err != nil {
				log.Error().Str("Task", "Cert Generating").Msgf("Could Not Decode Trust Store : %s", err)
				return
			}
			log.Info().Str("Task", "Cert Generating").Msgf("Certificate DN=%s", cert.DNSNames[0])
			log.Info().Str("Task", "Cert Generating").Msgf("Certificate SN=%s", cert.SerialNumber)
			log.Info().Str("Task", "Cert Generating").Msgf("Certificate Algo=%s", cert.PublicKeyAlgorithm)
			log.Info().Str("Task", "Cert Generating").Msgf("Certificate Expire=%s", cert.NotAfter.String())
			if err := os.MkdirAll("/cert", 0644); err != nil {
				log.Error().Str("Task", "Cert Generating").Msgf("Failed to Create Cert File Directory : %s", err)
				return
			}
			privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				log.Error().Str("Task", "Cert Generating").Msgf("Could Not Encode PrivateKey : %s", err)
				return
			}
			var caBuffer bytes.Buffer
			for _, caCert := range ca {
				caBuffer.Write(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: caCert.Raw,
				}))
			}
			caPEM, err := ioutil.ReadAll(&caBuffer)
			if err = ioutil.WriteFile("/cert/cert.pem", pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}), 0644); err != nil {
				log.Error().Str("Task", "Cert Generating").Msgf("Could Not Write Cert PEM : %s", err)
				return
			}
			if err = ioutil.WriteFile("/cert/privkey.pem", pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privateKeyDER,
			}), 0644); err != nil {
				log.Error().Str("Task", "Cert Generating").Msgf("Could Not Write Private Key : %s", err)
				return
			}
			if err = ioutil.WriteFile("/cert/chain.pem", caPEM, 0644); err != nil {
				log.Error().Str("Task", "Cert Generating").Msgf("Could Not Write CA Chain PEM : %s", err)
				return
			}
			if err = ioutil.WriteFile("/cert/fullchain.pem", append(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}), caPEM...), 644); err != nil {
				log.Error().Str("Task", "Cert Generating").Msgf("Could Not Write Fullchain PEM : %s", err)
				return
			}
			err = ioutil.WriteFile("/cert/host", []byte(cert.DNSNames[0]), 0644)
			if err != nil {
				log.Error().Str("Task", "Cert Generating").Msgf("Could Not Write Hentai@Home Network Host File : %s", err)
				return
			}
			log.Info().Str("Task", "Cert Generating").Msg("Certificate Generated!")
			return
		}
	}()
	// Shutdown Handler
	go func() {
		<-sigChannel
		log.Info().Str("Task", "Graceful Shutdown").Msg("Shutting Down Hentai@Home...")
		if err := process.Process.Signal(syscall.SIGINT); err != nil {
			log.Fatal().Str("Task", "Graceful Shutdown").Msgf("An Error was Occurred while Shutting Down Hentai@Home Process : %s", err)
			done <- nil
			return
		}
		_ = process.Wait()
		done <- nil
		return
	}()
	go func() {
		err := process.Wait()
		log.Info().Str("Task", "Graceful Shutdown").Msgf("Hentai@Home Process Exited : %s", err.Error())
		done <- nil
	}()
	<-done
	return
}

func download() {
	var fileWriter bytes.Buffer

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://repo.e-hentai.org/hath/HentaiAtHome_%s.zip", HathVersion), nil)
	res, err := http.DefaultClient.Do(req)
	defer func() {
		err := res.Body.Close()
		if err != nil {
			log.Fatal().Msgf("Failed to Download Hentai@Home : %s\n", err)
			os.Exit(10)
		}
	}()
	if err != nil {
		log.Fatal().Str("Task", "Download Hentai@Home").Msgf("Failed to Download Hentai@Home : %s\n", err)
		os.Exit(10)
	}
	bar := progressbar.DefaultBytes(res.ContentLength, "Downloading Hentai@Home")
	if _, err = io.Copy(io.MultiWriter(bar, &fileWriter), res.Body); err != nil {
		log.Fatal().Str("Task", "Download Hentai@Home").Msgf("Failed to Download Hentai@Home : %s\n", err)
		os.Exit(10)
	}
	file := fileWriter.Bytes()
	zipReader, _ := zip.NewReader(bytes.NewReader(file), int64(len(file)))
	f, err := zipReader.Open("HentaiAtHome.jar")
	if err != nil {
		log.Fatal().Str("Task", "Download Hentai@Home").Msgf("Failed to Extract Hentai@Home : %s\n", err)
		os.Exit(15)
	}
	hathFile, err := io.ReadAll(f)
	if err != nil {
		log.Fatal().Str("Task", "Download Hentai@Home").Msgf("Failed to Extract Hentai@Home : %s\n", err)
		os.Exit(15)
	}
	err = ioutil.WriteFile("/hath/hath.jar", hathFile, 0655)
	if err != nil {
		log.Fatal().Str("Task", "Download Hentai@Home").Msgf("Could Not Write Hentai@Home File : %s\n", err)
		os.Exit(20)
	}
	fmt.Println("Download Completed")
	return
}

func createCredential(clientId, clientKey string) {
	if err := os.MkdirAll("/hath/data", 0644); err != nil {
		log.Fatal().Str("Task", "Credential Creation").Msgf("Failed to Create Credential File Directory : %s", err)
		os.Exit(40)
	}
	fs, err := os.OpenFile("/hath/data/client_login", os.O_CREATE|os.O_WRONLY, 644)
	if err != nil {
		log.Fatal().Str("Task", "Credential Creation").Msgf("Failed to Open Credential File : %s", err)
		os.Exit(20)
	}
	_, err = fs.WriteString(fmt.Sprintf("%s-%s", clientId, clientKey))
	if err != nil {
		log.Fatal().Str("Task", "Credential Creation").Msgf("Failed to Write Credential File : %s", err)
		os.Exit(25)
	}
}
