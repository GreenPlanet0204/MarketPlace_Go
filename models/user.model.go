package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID 			uuid.UUID 	`gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Name		string		`gorm:"type:varchar(40);not null"`
	Email 		string		`gorm:"unique;not null"`
	Password	string		`gorm:"not null"`
	Role		string		`gorm:"type:varchar(20);not null"`
	Provider	string		`gorm:"default:'local';"`
	Photo		string
	CreatedAt	time.Time	`gorm:"not null"`
	UpdatedAt	time.Time	`gorm:"not null"`

	Verified	bool		`gorm:"not null"`
	Code		string

	PasswordResetToken 	string
	PasswordResetAt		time.Time

	OtpEnabled	bool		`gorm:"default:false;"`
	OtpVerified	bool		`gorm:"default:false;"`
	OtpSecret	string
	OtpAuthUrl	string
}

type SignInInput struct {
	Email		string		`json:"email" binding:"required"`
	Password	string		`json:"password" binding:"required"`
}

type SignUpInput struct {
	Name			string		`json:"name" binding:"required"`
	Email			string		`json:"email" binding:"required"`
	Password		string		`json:"password" binding:"required"`
	PasswordConfirm string		`json:"password_confirm" binding:"required"`
	Photo			string		`json:"photo"`
}

type UserResponse struct {
	ID        uuid.UUID `json:"id,omitempty"`
	Name      string    `json:"name,omitempty"`
	Email     string    `json:"email,omitempty"`
	Role      string    `json:"role,omitempty"`
	Photo     string    `json:"photo,omitempty"`
	Provider  string    `json:"provider"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type OTPInput struct {
	ID		string `json:"user_id"`
	Token	string `json:"token"`
}

type ForgotPasswordInput struct {
	Email string `json:"email" binding:"required"`
}

type ResetPasswordInput struct {
	Password string `json:"password" binding:"required"`
	PasswordConfirm string `json:"passwordConfirm" binding:"required"`
}