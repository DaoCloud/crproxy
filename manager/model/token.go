package model

type Token struct {
	TokenID int64
	UserID  int64

	Account  string
	Password string
	Data     string
}
