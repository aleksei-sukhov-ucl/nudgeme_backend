package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

// checks if user exists
func handleCheckUser(db DataSource) func(echo.Context) error {
	return func(c echo.Context) error {
		user := new(User)
		// bind the parameters into the User object
		if err := c.Bind(user); err != nil {
			return err
		}

		exists, err := db.DoesUserExist(user.Identifier)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK,
			map[string]bool{"success": true, "exists": exists})
	}
}

// adds a user to the database if the identifier is unused
func handleAddUser(db DataSource) func(echo.Context) error {
	return func(c echo.Context) error {
		user := new(User)
		if err := c.Bind(user); err != nil {
			return err
		}

		// ensure identifier is not already in use
		exists, err := db.DoesUserExist(user.Identifier)
		if err != nil {
			return err
		} else if exists {
			return failStatus(c, "Identifier already exists.")
		}

		// hash plaintext password (which is secure thanks to HTTPS)
		digest, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		err = db.InsertUser(user.Identifier, digest)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]bool{"success": true})
	}
}

// handles request to submit data to another user.
//
// If overwrite is false, it will not overwrite data between User A and User B.
func handleNewMessage(db DataSource, tableName string, overwrite bool) func(echo.Context) error {
	return func(c echo.Context) error {
		newMessage := new(NewMessageJSON)
		if err := c.Bind(newMessage); err != nil {
			return err
		}

		valid, err := db.isValidPassword(newMessage.Identifier_from, newMessage.Password)
		if err != nil {
			return err
		} else if !valid {
			return failStatus(c, "Password doesn't match expected.")
		}

		isPending, err := db.IsMessagePending(tableName, newMessage.Identifier_from,
			newMessage.Identifier_to)
		if err != nil {
			return err
		}

		toAdd, err := json.Marshal(newMessage.Data)
		if err != nil {
			return err
		}

		err = db.AddMessage(tableName, newMessage.Identifier_from, newMessage.Identifier_to,
			string(toAdd), overwrite && isPending)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]bool{"success": true})
	}
}

// handles a request to get unread messages for a given user
func handleGetMessage(db DataSource, tableName string) func(echo.Context) error {
	return func(c echo.Context) error {
		user := new(User)
		if err := c.Bind(user); err != nil {
			return err
		}

		valid, err := db.isValidPassword(user.Identifier, user.Password)
		if err != nil {
			return err
		} else if !valid {
			return failStatus(c, "Password doesn't match expected.")
		}

		messages, err := db.GetMessages(tableName, user.Identifier)
		if err != nil {
			return err
		}

		err = db.DeleteMessages(tableName, user.Identifier)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, messages)
	}
}

// data used in add_friend.html
type AddFriendTemplate struct {
	Identifier string
	PubKey     string
}

/// ref:https://golang.cafe/blog/golang-zip-file-example.html

func export(c echo.Context) error {
	secret := c.QueryParam("secret")
	// Creating a zip
	zipName := "archive.zip"
	archive, err := os.Create(zipName)
	if err != nil {
		panic(err)
	}
	defer archive.Close()
	zipWriter := zip.NewWriter(archive)

	pwd, _ := os.Getwd()
	files, err := ioutil.ReadDir(pwd + "/Audio")
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.Name() != ".DS_Store" {
			encryptedImage, err := ioutil.ReadFile("Audio/" + f.Name())
			if err != nil {
				panic(err)
			}
			//step 2
			plainImage := DecryptAES(encryptedImage, []byte(secret))
			var fileName = f.Name()
			error := WriteFile(plainImage, fileName)
			if error != nil {
				log.Fatalln(error)
			}
			f1, err := os.Open(fileName)
			if err != nil {
				panic(err)
			}
			w1, err := zipWriter.Create(fileName)
			if err != nil {
				panic(err)
			}
			if _, err := io.Copy(w1, f1); err != nil {
				panic(err)
			}

			defer f1.Close()
			defer os.Remove(fileName)
		}
	}
	zipWriter.Close()
	defer os.Remove(zipName)
	return c.JSON(http.StatusOK, c.Attachment(zipName, zipName))
}

func DecryptAES(cipherData, secret []byte) (plainData []byte) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonceSize := gcm.NonceSize()

	nonce, ciphertext := cipherData[:nonceSize], cipherData[nonceSize:]
	plainData, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}
	return
}

func handleAddFriend(c echo.Context) error {
	identifier := c.QueryParam("identifier")
	pubKey := c.QueryParam("pubKey")

	if isValidIDAndKey(identifier, pubKey) {
		return c.Render(http.StatusOK, "add_friend.html", AddFriendTemplate{
			Identifier: identifier,
			PubKey:     pubKey,
		})
	}
	return c.String(http.StatusBadRequest, "That link doesn't look right.")
}

// returns true if both id and key are valid
func isValidIDAndKey(id string, key string) bool {
	if len(id) == 0 || len(key) == 0 {
		return false
	}
	if len(key) < 62 {
		return false
	}
	return strings.HasPrefix(key, "-----BEGIN RSA PUBLIC KEY-----") &&
		strings.HasSuffix(key, "-----END RSA PUBLIC KEY-----")
}

// returns true if given password matches the password linked with identifier in DB
func verifyIdentity(db DataSource, identifier string, password string) bool {
	isValid, err := db.isValidPassword(identifier, password)
	println(err)
	return isValid
}

func failStatus(c echo.Context, reason string) error {
	return c.JSON(http.StatusBadRequest,
		map[string]interface{}{"success": false, "reason": reason})
}
