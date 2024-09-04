package proutils

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type (
	PasswordHasher struct{}
)

// This method hashes a string object using bcrypt
func (p *PasswordHasher) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("could not hash password: %s", err.Error())
	}
	return string(hash), nil
}

// This method compares a hashed password with its actual unhashed value -> pwd, hash
func (p *PasswordHasher) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{}
}
