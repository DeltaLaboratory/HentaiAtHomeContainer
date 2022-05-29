package HentaiAtHomeContainer

import (
	"fmt"
	"net/http"
)

const HATH_VERSION = "1.6.1"

func main() {
	r, err := http.Get(fmt.Sprintf("https://repo.e-hentai.org/hath/HentaiAtHome_%s.zip", HATH_VERSION))
	if err != nil {
		fmt.Printf("Failed to Download Hentai@Home : %s\n", err)
	}
}