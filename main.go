/*
log2gelf

A simple daemon that reads a file (tail -f style)
and sends every line as GELF/UDP.

Intended for nginx access logs -- so it does some special
character encoding/escaping for that format.

2014, DECK36 GmbH & Co. KG, <martin.schuette@deck36.de>
*/
package main

import (
	"flag"
	"fmt"
	"github.com/ActiveState/tail"
	"github.com/DECK36/go-gelf/gelf"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"bytes"
	"encoding/json"
	"strconv"
)

const thisVersion = "0.1"
const thisProgram = "log2gelf"

// Logline indicates what variables are our payload data,
// to improve readability (hopefully)
type Logline []byte

// CommandLineOptions holds all command line options
type CommandLineOptions struct {
	filename     *string
	gelfServer   *string
	gelfPort     *int
	verbose      *bool
	nofollow     *bool
}

var options CommandLineOptions

func init() {
	// this does not look right...
	// I am looking for a pattern how to group command line arguments in a struct
	options = CommandLineOptions{
		flag.String("file", "/var/log/syslog", "filename to watch"),
		flag.String("server", "localhost", "Graylog2 server"),
		flag.Int("port", 12201, "Graylog2 GELF/UDP port"),
		flag.Bool("v", false, "Verbose output"),
		flag.Bool("n", false, "Quit after file is read, do not wait for more data, do not read/write state"),
	}
	flag.Parse()
}

func readFileInode(fname string) uint64 {
	var stat syscall.Stat_t

	err := syscall.Stat(fname, &stat)
	if err != nil {
		return 0
	}
	return stat.Ino
}

// readStateFile gets previously saved file stat, i.e. inode and offset
func readStateFile(fname string, statefile string, currentInode uint64) (offset int64) {
	var time int64
	var inode uint64
	offset = 0

	stateline, err := ioutil.ReadFile(statefile)
	if err != nil {
		return // no state
	}

	n, err := fmt.Sscanf(string(stateline), "Offset %d Time %d Inode %d\n",
		&offset, &time, &inode)
	if n != 3 || err != nil {
		log.Printf("ignoring statefile, cannot parse data in %s: %v", statefile, err)
		return
	}

	if currentInode != inode {
		log.Printf("not resuming file %s, changed inode from %d to %d\n",
			fname, inode, currentInode)
		return
	}

	log.Printf("resume logfile tail of file %s (inode %d) at offset %d\n",
		fname, inode, offset)
	return offset
}

// write inode and offset to continue later
func writeStateFile(statefile string, inode uint64, offset int64) {
	data := []byte(fmt.Sprintf("Offset %d Time %d Inode %d\n",
		offset, time.Now().UTC().Unix(), inode))
	ioutil.WriteFile(statefile, data, 0664)
}

// readLogsFromFile reads log lines from file and send them to `queue`
// notify `shutdown` when file is completely read
func readLogsFromFile(fname string, queue chan<- Logline, shutdown chan<- string, savestate <-chan bool) {
	var statefile string
	var offset int64
	var inode uint64
	var doFollowFile bool = !*options.nofollow

	if *options.verbose {
		log.Printf("readLogsFromFile: dofollow=%v", doFollowFile)
	}

	if doFollowFile {
		statefile = fname + ".state"
		inode     = readFileInode(fname)
		offset    = readStateFile(fname, statefile, inode)
	}

	// setup
	config := tail.Config{
		Follow:    doFollowFile,
		ReOpen:    doFollowFile,
		MustExist: true,
		Logger:    tail.DiscardingLogger,
		Location: &tail.SeekInfo{
			Offset: offset,
			Whence: 0,
		},
	}
	t, err := tail.TailFile(fname, config)
	if err != nil {
		shutdown <- fmt.Sprintf("cannot tail file %s: %v", fname, err)
	} else if *options.verbose {
		log.Printf("opened log file %s", fname)
	}

	// now just sleep and wait for input and control channel
	for {
		select {
		case line := <-t.Lines:
			if line != nil {
				queue <- Logline(line.Text)
			} else {
				shutdown <- "Logfile closed"
				return
			}
		case <-savestate:
			offset, _ := t.Tell()
			if doFollowFile {
				writeStateFile(statefile, inode, offset)
			}
			if *options.verbose {
				log.Printf("reading %s, now at offset %d", fname, offset)
			}
		}
	}
}

// convert JSON (possibly already GELF) input to GELF
func buildGelfMessageJSON(message []byte) (gm gelf.Message, err error) {
	// list of "reserved" field names
	// cf. https://github.com/Graylog2/graylog2-server/blob/0.20/graylog2-plugin-interfaces/src/main/java/org/graylog2/plugin/Message.java#L61 and #L81
	// Go does not allow const maps :-/
	gelfReservedField := map[string]bool{
		"_id":     true,
		"_ttl":    true,
		"_source": true,
		"_all":    true,
		"_index":  true,
		"_type":   true,
		"_score":  true,
	}

	var emptyinterface interface{}
	err = json.Unmarshal(message, &emptyinterface)
	if err != nil {
		if *options.verbose {
			log.Printf("Cannot parse JSON, err: %v, msg: '%s'", err, message)
		}
		return
	}
	jm := emptyinterface.(map[string]interface{})

	// rename reserved field names (with and w/o '_')
	// note: we do not double check if 'renamed_xyz' is already present
	for k, v := range jm {
		if gelfReservedField[k] {
			jm["renamed"+k] = v
			delete(jm, k)
		} else if gelfReservedField["_"+k] {
			jm["renamed_"+k] = v
			delete(jm, k)
		}
	}

	// ensure some required fields are set, use defaults if missing
	var gelfHostname string = "unknown_amqp"
	if _, ok := jm["host"]; ok {
		gelfHostname = jm["host"].(string)
	}

	var gelfShortMsg string
	if _, ok := jm["short_message"]; ok {
		gelfShortMsg = jm["short_message"].(string)
	}

	var gelfTimestamp float64
	if _, ok := jm["timestamp"]; ok {
		switch tsval := jm["timestamp"].(type) {
		case float64:
			gelfTimestamp = tsval
		case string:
			gelfTimestamp, _ = strconv.ParseFloat(tsval, 64)
		}
	}

	syslogLevelMapping := map[string]int32{
		"emerg":    0,
		"alert":    1,
		"crit":     2,
		"critical": 2,
		"error":    3,
		"warn":     4,
		"warning":  4,
		"notice":   5,
		"info":     6,
		"debug":    7,
	}
	var gelfLevel int32 = 6 // info
	if _, ok := jm["level"]; ok {
		switch tsval := jm["level"].(type) {
		case int32:
			gelfLevel = tsval
		case string:
			gelfLevel = syslogLevelMapping[tsval]
		}
	}

	var gelfVersion string = "1.1"
	if _, ok := jm["version"]; ok {
		gelfVersion = jm["version"].(string)
	}

	gm = gelf.Message{
		Version:  gelfVersion,
		Host:     gelfHostname,
		Short:    gelfShortMsg,
		TimeUnix: gelfTimestamp,
		Level:    gelfLevel,
		Extra:    jm,
	}
	return gm, nil

}

// package text input in GELF
func buildGelfMessageText(message []byte) (gm gelf.Message, err error) {
	gm = gelf.Message{
		Version:  "1.1",
		Host:     "unknown",
		Short:    string(message),
		TimeUnix: 0.0,
		Level:    6, // info
		Extra:    map[string]interface{}{},
	}
	return gm, nil
}

func buildGelfMessage(message []byte) (gm gelf.Message, err error) {
	message = bytes.TrimSpace(message)
	if message[0] == '{' && message[len(message)-1] == '}' {
		if *options.verbose {
			log.Printf("buildGelfMessageJSON(%s)\n", message)
		}
		gm, err = buildGelfMessageJSON(message)
	} else {
		if *options.verbose {
			log.Printf("buildGelfMessageText(%s)\n", message)
		}
		gm, err = buildGelfMessageText(message)
	}
	return
}

func writeLogsToUdp(queue <-chan Logline, done chan error) {
	graylogAddr := fmt.Sprintf("%s:%d", *options.gelfServer, *options.gelfPort)
	gelfWriter, err := gelf.NewWriter(graylogAddr)
	if err != nil {
		done <- fmt.Errorf("Cannot create gelf writer: %v", err)
		return
	}

	for line := range queue {
		gm, err := buildGelfMessage(line)
		if err != nil {
			if *options.verbose {
				log.Printf("Rejected msg: %#v\n", line)
			}
			continue
		}
		if *options.verbose {
			log.Printf("sent msg: %f %s\n", gm.TimeUnix, gm.Short)
		}
		err = gelfWriter.WriteMessage(&gm)
		if err != nil {
			done <- fmt.Errorf("Cannot send gelf msg: %v", err)
			continue
		}
	}
	done <- fmt.Errorf("done")
	return
}

// let the OS tell us to shutdown
func osSignalHandler(shutdown chan<- string) {
	var sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	sig := <-sigs  // this is the blocking part

	go func(){
		time.Sleep(2*time.Second)
		log.Fatalf("shutdown was ignored, bailing out now.\n")
	}()

	shutdown <- fmt.Sprintf("received signal %v", sig)
}

func main() {
	if *options.verbose {
		log.Printf("Start %s %s", thisProgram, thisVersion)
	}
	// let goroutines tell us to shutdown (on error)
	var sigShutdown  = make(chan string)
	var fileShutdown = make(chan string)
	var udpShutdown  = make(chan error)
	// the main data queue, between reader and writer goroutines
	var queue = make(chan Logline)

	// let the OS tell us to shutdown
	go osSignalHandler(sigShutdown)

	// tell goroutine to save state before shutdown
	var savestate = make(chan bool)
	go readLogsFromFile(*options.filename, queue, fileShutdown, savestate)

	go writeLogsToUdp(queue, udpShutdown)

	// keep track of last offset
	ticker := time.NewTicker(time.Second * 2)
	go func() {
		for _ = range ticker.C {
			savestate <- true
		}
	}()

	select {
	case message := <-sigShutdown:
		if *options.verbose {
			log.Println("sigShutdown:", message)
		}
	case message := <-fileShutdown:
		if *options.verbose {
			log.Println("fileShutdown:", message)
		}
	case message := <-udpShutdown:
		if *options.verbose {
			log.Println("udpShutdown:", message)
		}
		savestate <- true  // file reader still alive
	}
	if *options.verbose {
		log.Println("The End.")
	}
}
