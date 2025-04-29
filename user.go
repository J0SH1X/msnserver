package main

import(
	"gorm.io/datatypes"
	"time"
	"net/http"
	"gorm.io/gorm"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
)

type User struct {
	ID                int            `gorm:"primaryKey"`
	UUID              string         `gorm:"unique"`
	Email             string         `gorm:"unique"`
	Username          string         `gorm:"unique"`
	Name              string
	FriendlyName      string
	Message           *string
	MessageLastModified time.Time
	NameLastModified  time.Time
	Password          string
	Verified          bool
	FrontData         datatypes.JSON
	DateCreated       time.Time
	DateLogin         *time.Time
	Contacts          datatypes.JSON `gorm:"-"`
	SessionToken 	  string
	IP 				  string
}


func addUser(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error encrypting password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Set timestamps
	user.DateCreated = time.Now()
	user.MessageLastModified = time.Now()
	user.NameLastModified = time.Now()

	// Save to database
	if err := db.Create(&user).Error; err != nil {
		http.Error(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusInternalServerError)
		return
	}

	// Never return the hashed password in the response
	user.Password = ""
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func saveSessionToken(userID int, sessionToken string, db *gorm.DB) error {
    result := db.Model(&User{}).Where("id = ?", userID).Update("session_token", sessionToken)
    if result.Error != nil {
        log.Println("Error updating SessionToken:", result.Error)
        return result.Error
    }
    return nil
}