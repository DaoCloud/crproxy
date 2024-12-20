package model

type Login struct {
	LoginID int64
	UserID  int64

	Type     string
	Account  string
	Password string
}
