package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	// needed but not directly used
	_ "github.com/go-sql-driver/mysql"
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

type MapTemplate struct {
	MAPDATA string
	SUPCODE string
}

type SafeMapTemplate struct {
	mu   sync.Mutex
	mapT MapTemplate
}

const messageTableName = "unread_messages"
const nudgeTableName = "user_nudge"

// NOTE: map demo has fixed data
var mapDemoTemplate MapTemplate = MapTemplate{}

var mapTemplate SafeMapTemplate = SafeMapTemplate{}

// registers the routes and handlers
func setupRoutes(e *echo.Echo, db *sql.DB, mydb DataSource) {
	initTemplateCache(db)

	e.GET("/", index)
	e.GET("/map", func(c echo.Context) error {
		mapTemplate.mu.Lock()
		mapT := mapTemplate.mapT
		mapTemplate.mu.Unlock()
		return c.Render(http.StatusOK, "map.html", mapT)
	})
	e.GET("/mapDemo", func(c echo.Context) error {
		return c.Render(
			http.StatusOK,
			"map.html",
			mapDemoTemplate)
	})
	// makes the geojson postcode data available:
	e.GET("/Postcode_Polygons/LONDON/*.geojson", func(c echo.Context) error {
		urlString := c.Request().URL.String()[1:]
		return c.File(urlString)
	})

	e.POST("/add-wellbeing-record", func(c echo.Context) error {
		record := new(WellbeingRecord)
		// bind the json body into `record`:
		if err := c.Bind(record); err != nil {
			return err
		}

		err := insertWellbeingRecord(*record, db)
		if err != nil {
			log.Print(err)
			return err
		}
		return c.JSON(http.StatusOK, map[string]bool{"success": true})
	})
	e.POST("/upload_audio", upload)
	// wellbeing sharing
	e.GET("/add-friend", handleAddFriend)
	e.POST("/user", handleCheckUser(mydb))
	e.POST("/user/new", handleAddUser(mydb))
	e.POST("/user/message", handleGetMessage(mydb, messageTableName))
	e.POST("/user/message/new", handleNewMessage(mydb, messageTableName, true))
	e.GET("/download_audio", export)
	e.GET("/download_data", func(c echo.Context) error {
		return c.File("get_audio_files.html")
	})

	// p2p nudge:
	// the back-end logic of passing around 'messages' is essentially the same,
	// it's up to the clients to define and handle the 'message' format.
	// Only difference is we don't overwrite pending messages.
	e.POST("/user/nudge", handleGetMessage(mydb, nudgeTableName))
	e.POST("/user/nudge/new", handleNewMessage(mydb, nudgeTableName, false))
}

func upload(c echo.Context) error {
	// Source
	// Since the key is 32 characters, i.e. 32 bytes, we are using AES-256 encryption.

	file, err := c.FormFile("audioFile")
	if err != nil {
		fmt.Println("Error retrieving file from form data")
		fmt.Println(err)
		return err
	}

	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	// UUID for files
	id := uuid.New()
	filename := strings.TrimSuffix(fmt.Sprintf("*-%s.m4a", id), "\n")

	// Destination
	audioFile, err := ioutil.TempFile("Audio", filename)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer audioFile.Close()

	fileBytes, err := ioutil.ReadAll(src)
	if err != nil {
		fmt.Println(err)
		return err
	}
	audioFile.Write(fileBytes)

	//Encryption of the file
	//Step 1
	secret := os.Getenv("AUDIO_PASSWORD")
	audioFileToEncrypt := ReadFile(audioFile.Name())

	//Step 2
	cipherImage := EncryptAES(audioFileToEncrypt, []byte(secret))
	error := WriteFile(cipherImage, audioFile.Name())
	if err != nil {
		log.Fatalln(error)
	}

	return c.JSON(http.StatusOK, audioFile.Name())
}

func EncryptAES(plainData, secret []byte) (cipherData []byte) {
	block, _ := aes.NewCipher(secret)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}

	cipherData = gcm.Seal(
		nonce,
		nonce,
		plainData,
		nil)

	return
}

func WriteFile(content []byte, filename string) (err error) {
	filepath := fmt.Sprintf("%s", filename)

	err = ioutil.WriteFile(filepath, content, 0644)
	if err != nil {
		return
	}
	return
}

func ReadFile(filename string) (content []byte) {
	filepath := fmt.Sprintf("%s", filename)
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Fatal(err.Error())
	}
	return
}

func initTemplateCache(mainDb *sql.DB) {
	mockDb := getDBConn("newdatabase")
	defer mockDb.Close()
	mapDemoTemplate = *getMapTemplate(mockDb, true)

	twoMinutes := time.Duration(2) * time.Minute
	go updateTemplateCache(mainDb, twoMinutes)
}

// updates safeMapTemplate every `duration`
func updateTemplateCache(db *sql.DB, duration time.Duration) {
	mapT := getMapTemplate(db, false)

	mapTemplate.mu.Lock()
	mapTemplate.mapT = *mapT
	mapTemplate.mu.Unlock()

	time.Sleep(duration)
	updateTemplateCache(db, duration)
}

func index(c echo.Context) error {
	greet := "Greetings! You may be looking for /map"
	return c.String(http.StatusOK, greet)
}

// inserts (a copy of) wellbeing record into the database
func insertWellbeingRecord(record WellbeingRecord, db *sql.DB) error {
	query := `INSERT INTO scores` +
		` (postCode, weeklySteps, wellbeingScore, sputumColour, mrcDyspnoeaScale, supportCode, date_sent, audioUrl, speechRateTest, testDuration)` +
		` VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := db.Exec(query,
		record.PostCode,
		record.WeeklySteps,
		record.WellbeingScore,
		record.sputumColour,
		record.mrcDyspnoeaScale,
		//record.ErrorRate,
		record.SupportCode,
		record.DateSent,
		record.AudioUrl,
		record.speechRateTest,
		record.testDuration) // sql automatically converts to date from yyyy-MM-dd
	return err
}

func getMapTemplate(db *sql.DB, isMock bool) *MapTemplate {
	// column names are case insensitive
	var tableName string
	//if isMock {
	//	tableName = "MOCK_DATA"
	//} else {
	//	tableName = "scores"
	//}
	tableName = "scores"
	postcodeGroupQuery := "SELECT postCode as name, AVG(wellBeingScore) as " +
		"avgscore, COUNT(postcode) as quantity FROM " + tableName + " GROUP BY (Postcode)"
	suppcodeGroupQuery := "SELECT Postcode as name, SupportCode as supportcode, " +
		"AVG(WellBeingScore)as score, COUNT(SupportCode) as entries FROM " +
		tableName + " GROUP BY SupportCode, PostCode;"
	rows, err := db.Query(postcodeGroupQuery)
	if err != nil {
		log.Print(err)
	}
	defer rows.Close()
	overlayDataMapDemo := make([]map[string]interface{}, 0)
	for rows.Next() {
		var name string
		var avgscore float32
		var quantity int
		if err := rows.Scan(&name, &avgscore, &quantity); err != nil {
			log.Print(err)
		}
		data := map[string]interface{}{"name": name, "avgscore": avgscore, "quantity": quantity}
		overlayDataMapDemo = append(overlayDataMapDemo, data)
	}
	if err := rows.Err(); err != nil {
		log.Print(err)
	}

	rows2, err := db.Query(suppcodeGroupQuery)
	if err != nil {
		log.Print(err)
	}
	defer rows2.Close()
	informationMap := make([]map[string]interface{}, 0)
	for rows2.Next() {
		var name string
		var supportCode string
		var score float32
		var entries int
		if err := rows2.Scan(&name, &supportCode, &score, &entries); err != nil {
			log.Print(err)
		}
		data := map[string]interface{}{"name": name,
			"supportcode": supportCode, "score": score, "entries": entries}
		informationMap = append(informationMap, data)
	}

	mapcodeData, err := json.Marshal(overlayDataMapDemo)
	supcodeData, err2 := json.Marshal(informationMap)
	if err != nil {
		log.Print(err)
		return nil
	}
	if err2 != nil {
		log.Print(err2)
		return nil
	}
	return &MapTemplate{string(mapcodeData), string(supcodeData)}
}
