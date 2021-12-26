package database

import (
	"fmt"
	"github.com/afzalabbasi/demo-code/model"
)

// GetUserByEmail method accepts an email
// Executes select query and returns information of
// User against that email.
func (db *DB) GetUserByEmail(email string) (user *model.User, err error) {
	userinfo := model.User{}
	err = db.Get(&userinfo, "SELECT * FROM users WHERE email = $1", email)
	if err != nil {
		return nil, err
	}
	return &userinfo, nil
}

// GetUserById method accepts a user id
// Executes select query and returns information of
// User against user id.
func (db *DB) GetUserById(Id int) (user *model.User, err error) {
	userinfo := model.User{}
	err = db.Get(&userinfo, "SELECT * FROM users WHERE _id = $1", Id)
	if err != nil {
		return nil, err
	}
	return &userinfo, nil
}

// GetUser method executes select query and returns information of
// User against user's info.
func (db *DB) GetUser() (user []*model.User, err error) {
	var userinfo []*model.User
	err = db.Get(&userinfo, "SELECT * FROM users")
	if err != nil {
		return nil, err
	}
	return userinfo, nil
}

func (db *DB) GetUserByRole(Id int) (user *model.User, err error) {
	userinfo := model.User{}
	err = db.Get(&userinfo, "SELECT * FROM users WHERE uRole = $1", Id)
	if err != nil {
		return nil, err
	}
	return &userinfo, nil
}

func (db *DB) ListUserAdvosir() (user *[]model.User, err error) {
	var userinfo []model.User
	err = db.Get(&userinfo, "SELECT * FROM users WHERE isAdvisor = true")
	if err != nil {
		return nil, err
	}
	return &userinfo, nil
}

func (db *DB) SetAdvisor(information model.MakeAdvisorInformation) (err error) {
	sqlStatement := `UPDATE users SET advisorID = $2 WHERE _id = $1;`
	_, err = db.Exec(sqlStatement, information.UserId, information.AdvisorId)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	return nil
}

func (db *DB) MakeAdvisor(userid int) (err error) {
	sqlStatement := `UPDATE users SET isadvisor = $2 WHERE _id = $1;`
	_, err = db.Exec(sqlStatement, userid, true)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	return nil
}

// GetUserByEmailAndPassword method accepts a user email and password,
// Executes select query and returns information of
// user against that user email and password.
func (db *DB) GetUserByEmailAndPassword(email string, password string) (user *model.User, err error) {
	userinfo := model.User{}
	err = db.Get(&userinfo, "SELECT * FROM users WHERE email = $1 AND password = $2", email, password)
	if err != nil {
		return nil, err
	}
	return &userinfo, nil
}

// Save method accepts a user model data and executes insertion query
// To sava data in our database.
func (db *DB) Save(user model.User) error {
	_, err := db.NamedExec("INSERT INTO users (firstname, lastname, email, password, advisorid, isverified, isadvisor, urole, onleave, parentemail, age, haveconcent, create_date, update_date) VALUES (:firstname, :lastname, :email, :password, :advisorid, :isverified, :isadvisor, :urole, :onleave, :parentemail, :age, :haveconcent, :create_date, :update_date)", user)
	return err
}

// UpdateUser method accepts a user model data and executes update query
// To update record in our database.
func (db *DB) UpdateUser(user model.User) (*model.User, error) {
	sqlStatement := `UPDATE users SET firstname = $2, lastname = $3, email = $4, advisorid = $5, urole = $6, isverified = $7, isadvisor = $8, onleave = $9, parentemail = $10, age = $11, haveconcent =$12 WHERE _id = $1;`
	_, err := db.Exec(sqlStatement, user.ID, user.FirstName, user.LastName, user.Email, user.AdvisorId, user.Urole, user.IsVerified, user.IsAdvisor, user.OnLeave, user.ParentEmail, user.Age, user.HaveConcent)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	return &user, nil
}

// VerifyUser method accepts a user model data and
// Executes update query to set verification flag true
// In database.
func (db *DB) VerifyUser(user model.User) error {
	sqlStatement := `UPDATE users SET isverified = $2 WHERE _id = $1;`
	_, err := db.Exec(sqlStatement, user.ID, user.IsVerified)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	return nil
}

// ResetPassword method accepts a user password and
// Executes update query to update password
// In database.
func (db *DB) ResetPassword(user model.User, password string) error {
	sqlStatement := `UPDATE users SET password =$2 WHERE _id = $1;`
	res, err := db.Exec(sqlStatement, user.ID, password)
	if err != nil {
		return nil
		fmt.Println(err.Error())
	}
	count, err := res.RowsAffected()
	if err != nil {
		return nil
	}
	fmt.Println(count)
	return nil
}
