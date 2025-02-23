package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

//go:embed templates/*.html
var templateFS embed.FS

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
	AdminEmail = "admin@example.com"
	AdminPassword = "admin123"
	log.Printf("ADMIN_EMAIL set to: %s", AdminEmail)
	log.Printf("ADMIN_PASSWORD set to: %s", AdminPassword)
}

func safeHTML(html string) template.HTML {
	return template.HTML(html)
}

func printRoutes() {
	routes := []string{
		"GET  /error",
		"GET  /login",
		"POST /login",
		"GET  /register",
		"POST /register",
		"GET  /reset-password",
		"POST /reset-password",
		"GET  /change-password",
		"POST /change-password",
		"GET  /user-emails",
	}

	fmt.Println("Available Routes:")
	for _, route := range routes {
		fmt.Println(route)
	}
}

func main() {
	printRoutes()

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
	tmpls := template.Must(template.New("").Funcs(template.FuncMap{
		"htmlsafe": safeHTML,
	}).ParseFS(templateFS, "templates/*.html"))

	http.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		tmpls.ExecuteTemplate(w, "error.html", nil)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			tmpls.ExecuteTemplate(w, "login.html", nil)
		} else {
			email := r.PostFormValue("email")
			password := r.PostFormValue("password")
			var user User
			result := db.First(&user, "email = ?", email)
			if result.Error != nil {
				data := map[string]string{
					"Error": result.Error.Error(),
				}
				tmpls.ExecuteTemplate(w, "login.html", data)
				return
			}
			if user.Password != password {
				data := map[string]string{
					"Error": "Wrong Password",
				}
				tmpls.ExecuteTemplate(w, "login.html", data)
				return
			}
			if email == AdminEmail {
				data := map[string]string{
					"Message": fmt.Sprintf("Welcome, Admin! The flag is: <strong>%s</strong>", "FLAG{HARDCODED_FLAG}"),
				}
				err = tmpls.ExecuteTemplate(w, "welcome.html", data)
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
				err = tmpls.ExecuteTemplate(w, "welcome.html", data)
				if err != nil {
					http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
				}
			}
		}
	})

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			tmpls.ExecuteTemplate(w, "register.html", nil)
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
				tmpls.ExecuteTemplate(w, "register.html", data)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	})

	http.HandleFunc("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			tmpls.ExecuteTemplate(w, "reset-password.html", nil)
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
				tmpls.ExecuteTemplate(w, "reset-password.html", data)
				return
			}

			successCount := 0
			errorMessages := []string{}

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

				otpCode := uuidList[i]
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
			tmpls.ExecuteTemplate(w, "reset-password.html", data)
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
				tmpls.ExecuteTemplate(w, "change-password.html", data)
				return
			}
			data := map[string]string{
				"Otp": otp,
			}
			tmpls.ExecuteTemplate(w, "change-password.html", data)
		} else {
			otp := r.FormValue("otp")
			if otp == "" {
				log.Println("OTP parameter is missing")
				data := map[string]string{
					"Error": "OTP parameter is missing",
				}
				tmpls.ExecuteTemplate(w, "change-password.html", data)
				return
			}
			_, err := uuid.Parse(otp)
			if err != nil {
				log.Printf("Invalid OTP format: %v", err)
				data := map[string]string{
					"Error": "Invalid OTP format",
				}
				tmpls.ExecuteTemplate(w, "change-password.html", data)
				return
			}
			var users []User
			result := db.Find(&users)
			if result.Error != nil {
				log.Printf("Error finding users: %v", result.Error)
				data := map[string]string{
					"Error": "Error finding users",
				}
				tmpls.ExecuteTemplate(w, "change-password.html", data)
				return
			}
			var validUser User
			var validOtpIndex int = -1
			var foundValidOtp bool
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
							tmpls.ExecuteTemplate(w, "change-password.html", data)
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
				tmpls.ExecuteTemplate(w, "change-password.html", data)
				return
			}
			newPassword := r.PostFormValue("password")
			db.Model(&validUser).Update("password", newPassword)
			if len(validUser.Otps) > 0 && validOtpIndex >= 0 {
				validUser.Otps = append(validUser.Otps[:validOtpIndex], validUser.Otps[validOtpIndex+1:]...)
				db.Save(&validUser)
			}
			log.Println("Password updated successfully")
			data := map[string]string{
				"Message": "Password Updated!",
			}
			tmpls.ExecuteTemplate(w, "change-password.html", data)
		}
	})

	http.HandleFunc("/user-emails", func(w http.ResponseWriter, r *http.Request) {
		userId := r.URL.Query().Get("userid")
		if userId == "" {
			log.Println("Error: User ID parameter is missing")
			data := map[string]interface{}{
				"Error": "User ID parameter is missing",
			}
			renderTemplate(w, tmpls, data)
			return
		}
		_, err := uuid.Parse(userId)
		if err != nil {
			log.Println("Error: Invalid User ID format")
			data := map[string]interface{}{
				"Error": "Invalid User ID format",
			}
			renderTemplate(w, tmpls, data)
			return
		}
		var user User
		result := db.First(&user, "user_id = ?", userId)
		if result.Error != nil {
			log.Printf("Error: User not found - %v", result.Error)
			data := map[string]interface{}{
				"Error": "User not found",
			}
			renderTemplate(w, tmpls, data)
			return
		}
		var emails []Email
		result = db.Where("user_id = ?", userId).Find(&emails)
		if result.Error != nil {
			log.Printf("Error retrieving emails: %v", result.Error)
			data := map[string]interface{}{
				"Error": result.Error.Error(),
			}
			renderTemplate(w, tmpls, data)
			return
		}
		data := map[string]interface{}{
			"Emails": emails,
		}
		renderTemplate(w, tmpls, data)
	})

	fmt.Println("Starting server on http://localhost:8080")
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

func renderTemplate(w http.ResponseWriter, tmpls *template.Template, data map[string]interface{}) {
	if err := tmpls.ExecuteTemplate(w, "emails.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
	}
}
