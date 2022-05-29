package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"github.com/schollz/progressbar/v3"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
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
	fs, err := os.OpenFile("./hath.jar", os.O_CREATE|os.O_WRONLY, 0644)
	defer func(fs *os.File) {
		err := fs.Close()
		if err != nil {
			fmt.Printf("Failed to Close File : %s\n", err)
			os.Exit(25)
		}
	}(fs)
	if err != nil {
		fmt.Printf("Failed to Open File : %s\n", err)
		os.Exit(20)
	}
	if _, err := fs.Write(hathFile); err != nil {
		fmt.Printf("Failed to Write File : %s\n", err)
		os.Exit(25)
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
	if _, err := os.Stat("./hath.jar"); err != nil {
		fmt.Println("Hentai@Home is Missing, Download New One...")
		download()
	}
	if os.Getenv("CLIENT_ID") == "" || os.Getenv("CLIENT_KEY") == "" {
		fmt.Println("Client ID or Client Key is not set Properly.")
		os.Exit(30)
	}
	createCredential(os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_KEY"))
	fmt.Println("Starting Hentai@Home Process...")
	process := exec.Command("java", "-jar", "./hath.jar")
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
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
		done <- nil
	}()
	<-done
	return
}
