package database

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tidwall/buntdb"
)

const UsersTable = "users"

type User struct {
	Id           int    `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"`
	CreatedAt    int64  `json:"created_at"`
	LastLogin    int64  `json:"last_login"`
}

func (d *Database) usersInit() {
	d.db.CreateIndex("users_id", UsersTable+":*", buntdb.IndexJSON("id"))
	d.db.CreateIndex("users_username", UsersTable+":*", buntdb.IndexJSON("username"))
}

func (d *Database) usersCreate(username string, passwordHash string, role string) (*User, error) {
	_, err := d.usersGetByUsername(username)
	if err == nil {
		return nil, fmt.Errorf("user already exists: %s", username)
	}

	id, _ := d.getNextId(UsersTable)

	u := &User{
		Id:           id,
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now().UTC().Unix(),
		LastLogin:    0,
	}

	jf, _ := json.Marshal(u)

	err = d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(UsersTable, id), string(jf), nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (d *Database) usersGetByUsername(username string) (*User, error) {
	u := &User{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("users_username", d.getPivot(map[string]string{"username": username}), func(key, val string) bool {
			if err := json.Unmarshal([]byte(val), u); err != nil {
				return false
			}
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("user not found: %s", username)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (d *Database) usersGetById(id int) (*User, error) {
	u := &User{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("users_id", d.getPivot(map[string]int{"id": id}), func(key, val string) bool {
			if err := json.Unmarshal([]byte(val), u); err != nil {
				return false
			}
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("user ID not found: %d", id)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (d *Database) usersList() ([]*User, error) {
	users := []*User{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		tx.Ascend("users_id", func(key, val string) bool {
			u := &User{}
			if err := json.Unmarshal([]byte(val), u); err == nil {
				users = append(users, u)
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (d *Database) usersUpdate(id int, u *User) error {
	jf, _ := json.Marshal(u)

	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(UsersTable, id), string(jf), nil)
		return nil
	})
	return err
}

func (d *Database) usersDelete(id int) error {
	err := d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(d.genIndex(UsersTable, id))
		return err
	})
	return err
}

// Public methods

func (d *Database) CreateUser(username string, passwordHash string, role string) (*User, error) {
	return d.usersCreate(username, passwordHash, role)
}

func (d *Database) GetUserByUsername(username string) (*User, error) {
	return d.usersGetByUsername(username)
}

func (d *Database) GetUserById(id int) (*User, error) {
	return d.usersGetById(id)
}

func (d *Database) ListUsers() ([]*User, error) {
	return d.usersList()
}

func (d *Database) UpdateUser(id int, u *User) error {
	return d.usersUpdate(id, u)
}

func (d *Database) DeleteUser(id int) error {
	return d.usersDelete(id)
}

// Auth token storage for web session management

const authTokenPrefix = "auth_session:"

func (d *Database) StoreAuthToken(token string, username string) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(authTokenPrefix+token, username, nil)
		return err
	})
}

func (d *Database) GetAuthToken(token string) (string, error) {
	var username string
	err := d.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(authTokenPrefix + token)
		if err != nil {
			return err
		}
		username = val
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("auth token not found")
	}
	return username, nil
}

func (d *Database) DeleteAuthToken(token string) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(authTokenPrefix + token)
		return err
	})
}
