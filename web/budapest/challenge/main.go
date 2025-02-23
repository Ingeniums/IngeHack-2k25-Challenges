package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type OTP struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

type User struct {
	gorm.Model
	UserId   string `gorm:"unique"`
	Email    string `gorm:"unique"`
	Password string
	Otps     []OTP `gorm:"serializer:json"`
}

type Email struct {
	gorm.Model
	UserId    string
	Recipient string
	Message   string
}

var AdminEmail string
var AdminPassword string

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	AdminEmail = os.Getenv("ADMIN_EMAIL")
	AdminPassword = os.Getenv("ADMIN_PASSWORD")
}

func safeHTML(html string) template.HTML {
	return template.HTML(html)
}

func main() {
	db, err := gorm.Open(sqlite.Open("db.sqlite"), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to db")
	}
	err = db.Migrator().DropTable(&User{}, &Email{})
	if err != nil {
		log.Printf("Error dropping tables: %v", err)
	}
	db.AutoMigrate(&User{}, &Email{})
	adminUserId, _ := uuid.NewRandom()
	db.Create(&User{UserId: adminUserId.String(), Email: AdminEmail, Password: AdminPassword})
	http.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		templ := template.Must(template.ParseFiles("templates/error.html"))
		templ.Execute(w, nil)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			templ := template.Must(template.ParseFiles("templates/login.html"))
			templ.Execute(w, nil)
		} else {
			email := r.PostFormValue("email")
			password := r.PostFormValue("password")
			var user User
			result := db.First(&user, "email = ?", email)
			if result.Error != nil {
				data := map[string]string{
					"Error": result.Error.Error(),
				}
				templ := template.Must(template.ParseFiles("templates/login.html"))
				templ.Execute(w, data)
				return
			}
			if user.Password != password {
				data := map[string]string{
					"Error": "Wrong Password",
				}
				templ := template.Must(template.ParseFiles("templates/login.html"))
				templ.Execute(w, data)
				return
			}
			if email == AdminEmail {
				data := map[string]string{
					"Message": fmt.Sprintf("Welcome, Admin! The flag is: <strong>%s</strong>", os.Getenv("FLAG")),
				}
				templ, err := template.New("welcome.html").Funcs(template.FuncMap{
					"htmlsafe": safeHTML,
				}).ParseFiles("templates/welcome.html")
				if err != nil {
					http.Error(w, "Template parsing error: "+err.Error(), http.StatusInternalServerError)
					return
				}
				err = templ.Execute(w, data)
				if err != nil {
					http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
				}
				go func() {
					resetAdminPassword(db)
				}()
			} else {
				data := map[string]interface{}{
					"Email":      email,
					"AdminEmail": AdminEmail,
					"UserId":     user.UserId,
				}
				templ, err := template.New("welcome.html").Funcs(template.FuncMap{
					"htmlsafe": safeHTML,
				}).ParseFiles("templates/welcome.html")
				if err != nil {
					http.Error(w, "Template parsing error: "+err.Error(), http.StatusInternalServerError)
					return
				}
				err = templ.Execute(w, data)
				if err != nil {
					http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
				}
			}
		}
	})
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			templ := template.Must(template.ParseFiles("templates/register.html"))
			templ.Execute(w, nil)
		} else {
			email := r.PostFormValue("email")
			password := r.PostFormValue("password")
			userId, _ := uuid.NewRandom()
			user := User{UserId: userId.String(), Email: email, Password: password}
			result := db.Create(&user)
			if result.Error != nil {
				data := map[string]string{
					"Error": result.Error.Error(),
				}
				templ := template.Must(template.ParseFiles("templates/register.html"))
				templ.Execute(w, data)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	})

	http.HandleFunc("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			templ := template.Must(template.ParseFiles("templates/reset-password.html"))
			templ.Execute(w, nil)
		} else {
			if err := r.ParseMultipartForm(32 << 20); err != nil {
				log.Printf("Error parsing multipart form: %v", err)
				http.Error(w, "Error parsing form", http.StatusBadRequest)
				return
			}

			log.Printf("Form values: %v", r.MultipartForm.Value)

			emails := r.MultipartForm.Value["email[]"]
			log.Printf("emails array: %v", emails)

			if len(emails) == 0 {
				if emailValue := r.FormValue("email"); emailValue != "" {
					emails = []string{emailValue}
					log.Printf("Using fallback email: %s", emailValue)
				}
			}

			if len(emails) == 0 {
				log.Printf("No emails found in request")
				data := map[string]string{
					"Error": "No valid email provided",
				}
				templ := template.Must(template.ParseFiles("templates/reset-password.html"))
				templ.Execute(w, data)
				return
			}

			successCount := 0
			errorMessages := []string{}

			// Generate all UUIDs in quick succession
			uuidList := make([]string, len(emails))
			for i := range uuidList {
				uuid, err := uuid.NewUUID()
				if err != nil {
					log.Printf("Error generating UUID: %v", err)
					continue
				}
				uuidList[i] = uuid.String()
			}

			for i, email := range emails {
				email = strings.TrimSpace(email)
				if email == "" {
					continue
				}

				var user User
				result := db.First(&user, "email = ?", email)
				if result.Error != nil {
					errorMessages = append(errorMessages, fmt.Sprintf("Error for %s: %s", email, result.Error.Error()))
					continue
				}

				otpCode := uuidList[i] // Use pre-generated UUID
				expiryTime := time.Now().Add(2 * time.Hour)
				newOtp := OTP{
					Code:      otpCode,
					ExpiresAt: expiryTime,
				}

				user.Otps = append(user.Otps, newOtp)
				db.Save(&user)

				emailRecord := Email{
					UserId:    user.UserId,
					Recipient: email,
					Message:   fmt.Sprintf("Your OTP: <strong>%s</strong>. <a href='/change-password?otp=%s'>Click here to reset your password</a>. This OTP expires in 2 hours.", otpCode, otpCode),
				}
				db.Create(&emailRecord)
				successCount++
			}

			var message string
			if successCount > 0 {
				message = "Reset email sent successfully to the addresses!"
				if len(errorMessages) > 0 {
					message += " There were some errors: " + strings.Join(errorMessages, "; ")
				}
			} else if len(errorMessages) > 0 {
				message = "Failed to send reset emails: " + strings.Join(errorMessages, "; ")
			} else {
				message = "No emails were processed"
			}

			data := map[string]string{
				"Message": message,
			}
			templ := template.Must(template.ParseFiles("templates/reset-password.html"))
			templ.Execute(w, data)
		}
	})

	http.HandleFunc("/change-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			otp := r.URL.Query().Get("otp")
			_, err := uuid.Parse(otp)
			if err != nil {
				log.Printf("Invalid OTP format: %v", err)
				data := map[string]string{
					"Error": "Invalid OTP format",
				}
				templ := template.Must(template.ParseFiles("templates/change-password.html"))
				templ.Execute(w, data)
				return
			}
			templ := template.Must(template.ParseFiles("templates/change-password.html"))
			data := map[string]string{
				"Otp": otp,
			}
			templ.Execute(w, data)
		} else {
			otp := r.FormValue("otp")
			if otp == "" {
				log.Println("OTP parameter is missing")
				data := map[string]string{
					"Error": "OTP parameter is missing",
				}
				templ := template.Must(template.ParseFiles("templates/change-password.html"))
				templ.Execute(w, data)
				return
			}
			_, err := uuid.Parse(otp)
			if err != nil {
				log.Printf("Invalid OTP format: %v", err)
				data := map[string]string{
					"Error": "Invalid OTP format",
				}
				templ := template.Must(template.ParseFiles("templates/change-password.html"))
				templ.Execute(w, data)
				return
			}

			// Here's the problem: We need to find all users and check each one's OTPs
			var users []User
			result := db.Find(&users)
			if result.Error != nil {
				log.Printf("Error finding users: %v", result.Error)
				data := map[string]string{
					"Error": "Error finding users",
				}
				templ := template.Must(template.ParseFiles("templates/change-password.html"))
				templ.Execute(w, data)
				return
			}

			var validUser User
			var validOtpIndex int = -1
			var foundValidOtp bool

			// Check all users for a matching OTP
			for _, user := range users {
				for i, userOtp := range user.Otps {
					if userOtp.Code == otp {
						log.Printf("Found matching OTP for user with ID: %s, expires at: %v", user.UserId, userOtp.ExpiresAt)
						if time.Now().Before(userOtp.ExpiresAt) {
							validUser = user
							validOtpIndex = i
							foundValidOtp = true
							break
						} else {
							log.Printf("OTP has expired, expiry time was: %v, current time is: %v", userOtp.ExpiresAt, time.Now())
							data := map[string]string{
								"Error": "OTP has expired",
							}
							templ := template.Must(template.ParseFiles("templates/change-password.html"))
							templ.Execute(w, data)
							return
						}
					}
				}
				if foundValidOtp {
					break
				}
			}

			if !foundValidOtp {
				log.Println("Invalid or expired OTP - no matching OTP found")
				data := map[string]string{
					"Error": "Invalid or expired OTP",
				}
				templ := template.Must(template.ParseFiles("templates/change-password.html"))
				templ.Execute(w, data)
				return
			}

			// Update password
			newPassword := r.PostFormValue("password")
			db.Model(&validUser).Update("password", newPassword)

			// Remove the used OTP
			if len(validUser.Otps) > 0 && validOtpIndex >= 0 {
				validUser.Otps = append(validUser.Otps[:validOtpIndex], validUser.Otps[validOtpIndex+1:]...)
				db.Save(&validUser)
			}

			log.Println("Password updated successfully")
			data := map[string]string{
				"Message": "Password Updated!",
			}
			templ := template.Must(template.ParseFiles("templates/change-password.html"))
			templ.Execute(w, data)
		}
	})
	http.HandleFunc("/user-emails", func(w http.ResponseWriter, r *http.Request) {
		userId := r.URL.Query().Get("userid")
		if userId == "" {
			log.Println("Error: User ID parameter is missing")
			data := map[string]interface{}{
				"Error": "User ID parameter is missing",
			}
			renderTemplate(w, data)
			return
		}
		_, err := uuid.Parse(userId)
		if err != nil {
			log.Println("Error: Invalid User ID format")
			data := map[string]interface{}{
				"Error": "Invalid User ID format",
			}
			renderTemplate(w, data)
			return
		}
		var user User
		result := db.First(&user, "user_id = ?", userId)
		if result.Error != nil {
			log.Printf("Error: User not found - %v", result.Error)
			data := map[string]interface{}{
				"Error": "User not found",
			}
			renderTemplate(w, data)
			return
		}
		var emails []Email
		result = db.Where("user_id = ?", userId).Find(&emails)
		if result.Error != nil {
			log.Printf("Error retrieving emails: %v", result.Error)
			data := map[string]interface{}{
				"Error": result.Error.Error(),
			}
			renderTemplate(w, data)
			return
		}
		data := map[string]interface{}{
			"Emails": emails,
		}
		renderTemplate(w, data)
	})
	fmt.Println("Starting ...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
func resetAdminPassword(db *gorm.DB) {
	var admin User
	result := db.First(&admin, "email = ?", AdminEmail)
	if result.Error != nil {
		log.Fatal("Admin not found")
		return
	}
	db.Model(&admin).Update("password", AdminPassword)
	fmt.Println("Admin password reset successfully")
}
func renderTemplate(w http.ResponseWriter, data map[string]interface{}) {
	templ := template.Must(template.New("emails.html").Funcs(template.FuncMap{
		"htmlsafe": safeHTML,
	}).ParseFiles("templates/emails.html"))
	if err := templ.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
	}
}

func parseEmails(input string) []string {
	// Split by comma and trim whitespace
	rawEmails := strings.Split(input, ",")
	var emails []string

	for _, email := range rawEmails {
		trimmedEmail := strings.TrimSpace(email)
		if trimmedEmail != "" {
			emails = append(emails, trimmedEmail)
		}
	}

	return emails
}
