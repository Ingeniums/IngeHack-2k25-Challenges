package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		urlStr := queryParams.Get("url")
		if urlStr == "" {
			http.Error(w, "url parameter is missing", http.StatusBadRequest)
			return
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			http.Error(w, "invalid URL", http.StatusBadRequest)
			return
		}

		switch parsedURL.Scheme {
		case "http", "https":
			resp, err := http.Get(urlStr)
			if err != nil {
				http.Error(w, "failed to fetch the URL", http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(resp.StatusCode)
			_, err = io.Copy(w, resp.Body)
			if err != nil {
				http.Error(w, "failed to write response", http.StatusInternalServerError)
			}
		case "file":
			filePath := parsedURL.Path
			file, err := os.Open(filePath)
			if err != nil {
				http.Error(w, "failed to open file", http.StatusInternalServerError)
				return
			}
			defer file.Close()

			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, err = io.Copy(w, file)
			if err != nil {
				http.Error(w, "failed to write response", http.StatusInternalServerError)
			}
		default:
			http.Error(w, "unsupported URL scheme", http.StatusBadRequest)
		}
	})
	fmt.Println("Server is running on port 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}