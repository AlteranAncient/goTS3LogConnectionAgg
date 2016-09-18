package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"

	_ "github.com/mattn/go-sqlite3"
	"github.com/urfave/cli"
)

func interpretMessage(response string) string {
	r := regexp.MustCompile(`(error) id=(\d+) msg=(.*)`)
	rX := regexp.MustCompile(`(error) id=(\d+) msg=(.*) extra_msg=(.*)?`)

	var rawText string
	if rX.MatchString(response) {
		respFields := rX.FindStringSubmatch(response)
		rawText = respFields[3] + "\n" + respFields[4]
	} else {
		rawText = r.FindStringSubmatch(response)[3]
	}

	text := unescapeMessage(rawText)
	return strings.Title(text)
}

// LogRow - Stores info about a log row from TS3.
type LogRow struct {
	Time          time.Time
	LogType       string
	Module        string
	VirtualServer int
	Message       string
}

func interpretLogOutputFromSQ(response string) (logs []LogRow) {
	r := regexp.MustCompile(`l=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|?`)
	logRows := r.FindAllStringSubmatch(response, -1)
	for _, thisRow := range logRows {
		timeScrapMs := strings.Split(thisRow[1], ".")
		rowTime, err := time.Parse("2006-01-02 15:04:05", timeScrapMs[0])
		if err != nil {
			panic("Error parsing time from Log file.")
		}

		vsID, err := strconv.Atoi(strings.TrimSpace(thisRow[4]))
		if err != nil {
			// Assume it is the main server - use zero.
			vsID = 0
		}

		logRow := LogRow{
			Time:          rowTime,
			LogType:       thisRow[2],
			Module:        thisRow[3],
			VirtualServer: vsID,
			Message:       thisRow[5],
		}
		log.Printf("LogRow: %v", logRow)
		logs = append(logs, logRow)
	}
	return
}

func interpretLogOutputFromFile(response string) (logs []LogRow) {
	r := regexp.MustCompile(`(?m)(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)$`)
	logRows := r.FindAllStringSubmatch(response, -1)
	for _, thisRow := range logRows {
		timeScrapMs := strings.Split(thisRow[1], ".")
		rowTime, err := time.Parse("2006-01-02 15:04:05", timeScrapMs[0])
		if err != nil {
			panic("Error parsing time from Log file.")
		}

		vsID, err := strconv.Atoi(strings.TrimSpace(thisRow[4]))
		if err != nil {
			// Assume it is the main server - use zero.
			vsID = 0
		}

		logRow := LogRow{
			Time:          rowTime,
			LogType:       thisRow[2],
			Module:        thisRow[3],
			VirtualServer: vsID,
			Message:       thisRow[5],
		}
		logs = append(logs, logRow)
	}
	return
}

func unescapeMessage(response string) string {
	transformedResponse := strings.Replace(response, `\\`, `\`, -1)
	transformedResponse = strings.Replace(transformedResponse, `\/`, `/`, -1)
	transformedResponse = strings.Replace(transformedResponse, `\s`, ` `, -1)
	transformedResponse = strings.Replace(transformedResponse, `\p`, `|`, -1)
	return transformedResponse
}

func processScanner(scanner *bufio.Scanner) (output string, err error) {
	err = nil
	for scanner.Scan() {
		response := scanner.Text()
		// An OK should be the last thing we receive - don't let it overwrite output
		if strings.Contains(response, "msg=ok") {
			break
		}
		if strings.Contains(response, "error id=0") {
			output = interpretMessage(response)
			// log.Printf("No Errors, Output: %s", output)
		} else if strings.Contains(response, "error") {
			output = interpretMessage(response)
			// log.Printf("Error, Output: %s", output)
			err = errors.New(output)
			break
		} else {
			output = unescapeMessage(response)
			// log.Printf("Line, Output: %s", output)
		}
	}
	return output, err
}

func makeQuery(host string, username string, password string, dateTime string) {
	conn, connErr := net.Dial("tcp", host)
	if connErr != nil {
		log.Printf("Error connecting: %s", connErr.Error())
	}

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("%s", line)
		if strings.Contains(line, "Welcome to the TeamSpeak 3 ServerQuery interface") {
			break
		}
	}
	log.Println("End of scan.")

	sqCommand := fmt.Sprintf("login %s %s", username, password)
	log.Printf("Attempting serverquery login with user %s", username)
	// send to socket
	_, writeErr := fmt.Fprintf(conn, sqCommand+"\n")
	if writeErr != nil {
		log.Printf("Write Error: %s", writeErr.Error())
	}

	_, err := processScanner(scanner)
	if err != nil {
		log.Println(err.Error())
		panic("Error whilst logging in.")
	}

	sqCommand = fmt.Sprintf("use sid=%d", 1)
	log.Printf("Using Server ID 1")
	// send to socket
	_, writeErr = fmt.Fprintf(conn, sqCommand+"\n")
	if writeErr != nil {
		log.Printf("Write Error: %s", writeErr.Error())
	}

	_, err = processScanner(scanner)
	if err != nil {
		log.Println(err.Error())
		panic("Error whilst setting server ID.")
	}

	log.Println("Fetching logs...")
	var logs []LogRow
	for i := 0; i < 10; i++ {
		sqCommand = fmt.Sprintf("logview lines=%d reverse=%d instance=%d begin_pos=%d", 100, 1, 0, i*100)

		_, writeErr = fmt.Fprintf(conn, sqCommand+"\n")
		if writeErr != nil {
			log.Printf("Write Error: %s", writeErr.Error())
		}

		scanResult, err := processScanner(scanner)
		if err != nil {
			panic(err.Error())
		}

		logs = append(logs, interpretLogOutputFromSQ(scanResult)...)
	}

	log.Printf("Number of log rows recovered: %d", len(logs))
	processFileStats(logs, dateTime)
}

func processFileStats(logs []LogRow, dateTime string) {
	os.Remove("./stats.db")
	db, err := sql.Open("sqlite3", "./stats.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sqlCreate := "CREATE TABLE clients (id INTEGER PRIMARY KEY, date DATETIME, clientcount INTEGER, names TEXT); DELETE FROM clients;"
	_, err = db.Exec(sqlCreate)
	if err != nil {
		log.Printf("%q: %s\n", err, sqlCreate)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	stmt, err := tx.Prepare("INSERT INTO clients(date, clientcount, names) VALUES(?, ?, ?)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	var clients map[int]string
	clients = make(map[int]string)

	for _, thisRow := range logs {
		if thisRow.VirtualServer != 1 {
			// Skip this row - it doesn't relate to the Virtual Server we're interested in.
			continue
		}

		if strings.Contains(thisRow.Message, "listening on") {
			// Nuke and re-declare the map.
			clients = make(map[int]string)
		}
		if strings.Contains(thisRow.Message, "client connected") {
			pattern := regexp.MustCompile(`(?:client connected |client disconnected )(?:\')(.+)(?:\')\(id\:(\d+)\)`)
			clientDetails := pattern.FindStringSubmatch(thisRow.Message)
			clientID, _ := strconv.Atoi(clientDetails[2])
			clients[clientID] = clientDetails[1]
		}
		if strings.Contains(thisRow.Message, "client disconnected") {
			pattern := regexp.MustCompile(`(?:client connected |client disconnected )(?:\')(.+)(?:\')\(id\:(\d+)\)`)
			clientDetails := pattern.FindStringSubmatch(thisRow.Message)
			clientID, _ := strconv.Atoi(clientDetails[2])
			delete(clients, clientID)
		}
		_, err = stmt.Exec(thisRow.Time.Format("2006-01-02 15:04:05"), len(clients), printMapToString(clients))
		if err != nil {
			log.Fatal(err)
		}
	}
	tx.Commit()

	stmt, err = db.Prepare("SELECT clientcount, names FROM clients WHERE date <= ? ORDER BY date DESC LIMIT 1")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	var clientTTL int
	var clientNames string
	err = stmt.QueryRow(dateTime).Scan(&clientTTL, &clientNames)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Clients Connected: %d\n", clientTTL)
	fmt.Printf("%s", clientNames)
}

func printMapToString(clients map[int]string) string {
	var buffer bytes.Buffer

	for _, thisName := range clients {
		buffer.WriteString(thisName)
		buffer.WriteString(", ")
	}

	return strings.TrimRight(buffer.String(), ", ")
}

func loadFile(fileName string, dateTime string) {
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Printf("File not found: %s", err.Error())
		return
	}
	fileText := string(fileData)
	logs := interpretLogOutputFromFile(fileText)
	log.Printf("Rows Retrieved: %d", len(logs))
	processFileStats(logs, dateTime)
}

func main() {
	app := cli.NewApp()
	app.Name = "TS3 Server Log Consumer"
	app.Usage = "Consume TS3 server logs for (some) meaningful statistics."
	app.Version = "0.1.0 (Unsupported)"
	app.Compiled = time.Now()
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "David Mays",
			Email: "webmaster@alteranlabs.co.uk",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:        "serverquery",
			Aliases:     []string{"sq"},
			Usage:       "serverquery - Logs in to Server Query to pull the latest logs.",
			Description: "This is totally experimental and un-supported. If you are not using 'logappend=1' in your TS3 server config, you will probably want to use the file method instead.",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "host, H",
					Usage: "Hostname or IP of the TS3 Server",
				},
				cli.StringFlag{
					Name:  "port, P",
					Value: "10011",
					Usage: "Port of the TS3 Server Serverquery (not the client connection port).",
				},
				cli.StringFlag{
					Name:  "user, u",
					Value: "serveradmin",
					Usage: "Username of the TS3 Serverquery.",
				},
				cli.StringFlag{
					Name:  "password, p",
					Usage: "Password of the given TS3 Serverquery user. Will be prompted in console if left blank.",
				},
				cli.StringFlag{
					Name:  "datetime, d",
					Usage: "datetime to report population at given time",
				},
			},
			Action: func(c *cli.Context) error {
				fmt.Printf(`
This program is experimental and not officially supported. The serverquery feature is even more un-supported (if that is even a thing).
You may risk getting yourself banned from your TS ServerQuery for any of the following reasons:
 * Bad Credentials
 * Command Flood
If you want the easier route, I would recommend using the file method instead.

To continue: Press ENTER
To stop: Press CTRL + C
`)
				_, _ = bufio.NewReader(os.Stdin).ReadString('\n')

				if c.String("host") == "" {
					fmt.Println("You haven't specified a server host. Please do that with --host.")
					cli.ShowAppHelp(c)
					return nil
				}

				var port string
				if c.String("port") == "" {
					fmt.Println("No port specified. Assuming '10011' as default.")
					port = "10011"
				} else {
					port = c.String("port")
				}

				hoststring := fmt.Sprintf("%s:%s", c.String("host"), port)

				var user string
				if c.String("port") == "" {
					fmt.Println("No user specified. Assuming 'serveradmin' as default.")
					user = "serveradmin"
				} else {
					user = c.String("user")
				}

				var pass string
				if c.String("password") == "" {
					fmt.Print("Enter ServerQuery Password: ")
					bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
					if err != nil {
						fmt.Println("\nEror reading password.")
					}

					pass = string(bytePassword)
				} else {
					pass = c.String("password")
				}

				if c.String("datetime") == "" {
					fmt.Printf("You haven't specified a datetime stamp to check. Please do that with --datetime. Format should be '2016-12-30 15:04:05'.\n\n")
					cli.ShowAppHelp(c)
					return nil
				}

				makeQuery(hoststring, user, pass, c.String("datetime"))
				return nil
			},
		},
		{
			Name:        "file",
			Aliases:     []string{"f"},
			Usage:       "Loads the file specified and reports on the logs.",
			Description: "You can use cat *.log > somefile.log to create this.",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "file, f",
					Usage: "Will load the Server logs from `FILENAME`.",
				},
				cli.StringFlag{
					Name:  "datetime, d",
					Usage: "datetime to report population at given time",
				},
			},
			Action: func(c *cli.Context) error {
				if c.String("file") == "" {
					fmt.Print("You haven't specified a file name to load. Please do that with --file.\n\n")
					cli.ShowAppHelp(c)
					return nil
				}

				if c.String("datetime") == "" {
					fmt.Printf("You haven't specified a datetime stamp to check. Please do that with --datetime. Format should be '2016-12-30 15:04:05'.\n\n")
					cli.ShowAppHelp(c)
					return nil
				}

				loadFile(c.String("file"), c.String("datetime"))
				return nil
			},
		},
	}

	app.Run(os.Args)
}
