package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"

	"math/big"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

var x9ds7k3hYp string

var blackList = []string{
    "and",
    "html",
    "index",
    "js",
    "len",
    "not",
    "or",
    "print",
    "print",
    "printf",
    "println",
    "urlquery",
    "eq",
    "ne",
    "lt",
    "le",
    "ge",
    "slice",
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	x9ds7k3hYp = os.Getenv("FLAG")
	if x9ds7k3hYp == "" {
		log.Fatal("Error: FLAG environment variable is not set. Exiting.")
	}
}

func generateKey() string {
	baseKey := make([]byte, 32)
	if _, err := rand.Read(baseKey); err != nil {
		log.Fatal("Failed to generate base key:", err)
	}

	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal("Failed to generate salt:", err)
	}

	h := hmac.New(sha256.New, baseKey)
	h.Write(salt)

	return hex.EncodeToString(h.Sum(nil))
}

func randomColor() string {
	colors := []string{"#FF0000", "#00FF00", "#0000FF", "#FFFF00", "#00FFFF", "#FF00FF", "#C0C0C0", "#808080", "#800000", "#808000", "#008000", "#800080", "#008080", "#000080"}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(colors))))
	return colors[n.Int64()]
}

func main() {
	http.HandleFunc("/", handleTemplate)
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleTemplate(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")

	start := strings.Index(message, "{{")
	for start != -1 {
		end := strings.Index(message[start:], "}}")
		if end == -1 {
			break
		}
		end += start + 2

		insideBrackets := message[start+2 : end-2]
		messageParts := strings.Fields(insideBrackets)

		for _, messagePart := range messageParts {
			for _, b := range blackList {
				if messagePart == b {
					w.Write([]byte("Forbidden: " + messagePart + " detected in the input"))
					return
				}
			}
		}

		start = strings.Index(message[end:], "{{")
		if start != -1 {
			start += end
		}
	}

	secretKey := generateKey()

	if message == "" {
		w.Write([]byte(`
            <html>
                <head>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background-color: #121212;
                            color: white;
                            display: flex;
                            flex-direction: column;
                            align-items: center;
                            justify-content: center;
                            height: 100vh;
                            text-align: center;
                        }
                        .container {
                            max-width: 600px;
                            padding: 20px;
                            background: #1e1e1e;
                            border-radius: 10px;
                            box-shadow: 0 4px 10px rgba(255, 255, 255, 0.1);
                        }
                        textarea {
                            width: 100%;
                            height: 100px;
                            background: #2c2c2c;
                            color: white;
                            border: 1px solid #444;
                            padding: 10px;
                            border-radius: 5px;
                            resize: none;
                        }
                        button {
                            background-color: #007BFF;
                            color: white;
                            border: none;
                            padding: 10px 20px;
                            cursor: pointer;
                            margin-top: 10px;
                            border-radius: 5px;
                        }
                        button:hover {
                            background-color: #0056b3;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Dynamic Color Preview</h1>
                        <form method="GET">
                            <textarea name="message" placeholder="Enter your message"></textarea><br>
                            <button type="submit">Show Colored Text</button>
                        </form>
                    </div>
                </body>
            </html>
        `))
		return
	}

	data := map[string]interface{}{
		"hiddenKey": func() string { return secretKey },
		"getFlag":   func() string { return "try harder" },
		"revealFlag": func(k string) string {
			if k == secretKey {
				return x9ds7k3hYp
			}
			return "Wrong key"
		},
	}

	tmpl, err := template.New("userTemplate").Parse(message)
	if err != nil {
		w.Write([]byte("Error parsing template: " + err.Error()))
		return
	}

	var result strings.Builder
	err = tmpl.Execute(&result, data)
	if err != nil {
		w.Write([]byte("Error executing template: " + err.Error()))
		return
	}

	output := result.String()
	if strings.Contains(output, x9ds7k3hYp) {
		output = "Forbidden: ingehack detected in the output"
	}

	color := randomColor()
	coloredOutput := `<div style="color: ` + color + `;">` + output + `</div>`

	w.Write([]byte(`
        <html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #121212;
                        color: white;
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        height: 100vh;
                        text-align: center;
                    }
                    .container {
                        max-width: 600px;
                        padding: 20px;
                        background: #1e1e1e;
                        border-radius: 10px;
                        box-shadow: 0 4px 10px rgba(255, 255, 255, 0.1);
                    }
                    .preview {
                        background: #2c2c2c;
                        padding: 10px;
                        border-radius: 5px;
                        margin-top: 10px;
                        border: 1px solid #444;
                    }
                    a {
                        color: #00bcd4;
                        text-decoration: none;
                        font-weight: bold;
                        margin-top: 10px;
                        display: block;
                    }
                    a:hover {
                        color: #ff4081;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Dynamic Color Preview</h2>
                    <div class="preview">` + coloredOutput + `</div>
                    <a href="/">Try again</a>
                </div>
            </body>
        </html>
    `))
}
