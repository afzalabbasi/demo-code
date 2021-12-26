package model

import "time"

// User Model
type User struct {
	ID          int       `json:"_id" db:"_id"`
	FirstName   string    `json:"firstname" validate:"required"`
	LastName    string    `json:"lastname" validate:"required"`
	Email       string    `json:"email" validate:"required"`
	ParentEmail string    `json:"parentEmail"`
	Age         int       `json:"age" validate:"required"`
	HaveConcent bool      `json:"haveconcent"`
	Password    string    `json:"password,omitempty" validate:"required"`
	AdvisorId   int       `json:"advisorid"`
	Urole       int       `json:"urole"`
	IsVerified  bool      `json:"isVerified"`
	IsAdvisor   bool      `json:"isAdvisor"`
	OnLeave     bool      `json:"on_leave"`
	CreateDate  time.Time `json:"create_date" db:"create_date"`
	UpdateDate  time.Time `json:"update_date" db:"update_date"`
}

// Notification Model
type Notification struct {
	Userid     int       `json:"userid"  validate:"required"`
	Message    string    `json:"message"  validate:"required"`
	IsRead     bool      `json:"is_read"`
	CreateDate time.Time `json:"create_date" db:"create_date"`
	UpdateDate time.Time `json:"update_date" db:"update_date"`
}

// MakeAdvisorInformation model
type MakeAdvisorInformation struct {
	AdvisorId int `json:"advisorID"`
	UserId    int `json:"userid"`
}

// RoleInformation model
type RoleInformation struct {
	RoleId int `json:"role_id" validate:"required"`
}

// Login model
type Login struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// SuccessResponse model
type SuccessResponse struct {
	Data       interface{} `json:"data"`
	Message    string      `json:"message"`
	SubMessage string      `json:"sub_message"`
}

// BadResponse model
type BadResponse struct {
	Message    string `json:"message"`
	SubMessage string `json:"sub_message"`
}
