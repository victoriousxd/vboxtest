package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var l = log.New(os.Stdout, "", 0)
var el = log.New(os.Stderr, "", 0)
var pid = os.Getpid()
var regex = regexp.MustCompile(`audit.(?P<timestamp>.*):(?P<sequence>.*).: arch=(?P<arch>.*) syscall=(?P<syscall>\d+) (?:success=(?P<success>.*) exit=(?P<exit>.*))?[ ]*a0=(?P<a0>.*) a1=(?P<a1>.*) a2=(?P<a2>.*) a3=(?P<a3>.*) items=(?P<items>.*) ppid=(?P<ppid>.*) pid=(?P<pid>.*) auid=(?P<auid>.*) uid=(?P<uid>.*) gid=(?P<gid>.*) euid=(?P<euid>.*) suid=(?P<suid>.*) fsuid=(?P<fsuid>.*) egid=(?P<egid>.*) sgid=(?P<sgid>.*) fsgid=(?P<fsgid>.*) tty=(?P<tty>.*) ses=(?P<ses>.*) comm=(?P<comm>.*) exe=(?P<exe>.*)[ ]*(?:subj=(?P<subj>.*))? key=(?P<key>.*)`)
var network = getNetork()

type Interface struct {
	Iface    string    `json:"iface"`
	Networks []Network `json:"network_data"`
}

type Network struct {
	Ip  string `json:"ip"`
	Mac string `json:"mac"`
}

//All fields in any given syscall audit message

type Syscall struct {
	Network   []Interface `json:"interfaces"` // strings
	Comm      string      `json:"comm"`
	Exe       string      `json:"exe"`
	Subj      string      `json:"subj"`
	Key       string      `json:"key"`
	Tty       string      `json:"tty"`
	Per       string      `json:"per"`
	Seq       uint64      `json:"sequence"` // 64 bits
	Timestamp float64     `json:"timestamp"`
	Arch      uint64      `json:"arch"`
	A0        uint64      `json:"a0"`
	A1        uint64      `json:"a1"`
	A2        uint64      `json:"a2"`
	A3        uint64      `json:"a3"`
	Ses       uint64      `json:"ses"`
	Items     uint64      `json:"items"`
	Ppid      uint32      `json:"ppid"` // 32 bits
	Pid       uint32      `json:"pid"`
	Auid      uint32      `json:"auid"`
	Uid       uint32      `json:"uid"`
	Gid       uint32      `json:"gid"`
	Euid      uint32      `json:"euid"`
	Suid      uint32      `json:"suid"`
	Fsuid     uint32      `json:"fsuid"`
	Egid      uint32      `json:"egid"`
	Sgid      uint32      `json:"sgid"`
	Fsgid     uint32      `json:"fsgid"`
	Syscall   uint16      `json:"syscall"` //  16 bits
	Exit      uint16      `json:"exit"`
	Success   uint8       `json:"success"`
}

type executor func(string, ...string) error

func lExec(s string, a ...string) error {
	return exec.Command(s, a...).Run()
}

//set up gob encoder to write to stdout

var ignore = []string{"auditctl", "collectorSource"}

func main() {
	fmt.Println(os.Args)
	defaultTime, _ := time.ParseDuration("30s")
	//gets arguments from commandline input
	configFile := flag.String("config", "/home/go-audit.yaml", "Config file location")
	timerDuration := flag.Duration("time", defaultTime, "Specify time in format of (num)(unit)\n\ti.e. 5m = 5 minutes, 5s = 5 second.")
	programArgs := flag.String("exe", "", "Please type a command to run wrapped in quotes")

	//follow := flag.Bool("follow", false, "set to true if you want to follow a specific ")

	flag.Parse()

	//sets up a viper object with the config file provided
	config, err := loadConfig(*configFile)
	if err != nil {
		el.Fatal(err)
	}
	//sets up audit rules according to the config file
	if err := setRules(config, lExec); err != nil {
		el.Fatal(err)
	}
	bob := json.NewEncoder(os.Stdout)
	// set up interrupt handler
	GracefulExitHandler()
	// set up timer

	f, err := os.OpenFile("testlogfile", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	setUpTimer(*timerDuration)

	//fmt.Printf("settings: timer = %v, batchsize = %v\n\n", timerDuration, batchSize)
	t := time.Now()
	// start the wanted program
	if *programArgs != "" {
		argies := strings.Fields(*programArgs)
		fmt.Println("got some argies: ", argies)
		cmdexe := exec.Command(argies[0], argies[1:]...)

		cmdexe.Start()
		fmt.Print(cmdexe)
	}
	//testcmd := exec.Command("ausearch")
	for {

		cmd := exec.Command("ausearch", "--raw", "--start", t.Format("01/02/2006"), t.Format("15:04:05"))

		stdout, _ := cmd.StdoutPipe()

		cmd.Start()

		scanner := bufio.NewScanner(stdout)
		scanner.Split(SplitAt("\n"))
		for power && scanner.Scan() {
			m := scanner.Bytes()

			if bytes.HasPrefix(m, []byte("type=SYSCALL")) {
				//print(string(m))
				var sys Syscall

				sys.Network = network

				result := parseSyscall(&sys, m)
				if result {

					// should've encoded to json but didn't send over vm :(
					err := bob.Encode(&sys)
					log.Println(sys)
					if err != nil {
						el.Fatal(err)
					}
				}

			}
		}
		if !power {
			fmt.Println("Recording is complete. Pleasee press CTRL-C again to exit the audit program.")

			if err != nil {
				fmt.Println(err)
				return
			}
			return
		}
		cmd.Wait()
		t = time.Now()
	}
}

func getNetork() []Interface {
	addrs, _ := net.Interfaces()
	network := make([]Interface, 0)

	for _, addr := range addrs {
		add, _ := addr.Addrs()

		ip_macs := make([]Network, 0)
		for _, add := range add {
			ip_macs = append(ip_macs, Network{
				Mac: addr.HardwareAddr.String(),
				Ip:  add.String(),
			})
		}

		network = append(network, Interface{
			Iface:    addr.Name,
			Networks: ip_macs,
		})
	}

	return network
}

func parseSyscall(syscall *Syscall, m []byte) bool {
	match := regex.FindStringSubmatch(string(m))
	result := make(map[string]string)

	for i, name := range regex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}

	if value, ok := result["pid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		if pid != int(v) && pid != int(v) {
			syscall.Pid = uint32(v)
		} else {
			return false
		}
	}

	if value, ok := result["exe"]; ok {
		if value == "/home/meow/vBoxTest/collectorSource/collectorSource" || value == "/sbin/auditctl" {
			return false
		}

		syscall.Exe = value
	}

	if value, ok := result["comm"]; ok {
		if value == "auditctl" || value == "collectorSource" {
			return false
		}

		syscall.Comm = value
	}

	if value, ok := result["subj"]; ok {
		syscall.Subj = value
	}
	if value, ok := result["key"]; ok {
		syscall.Key = value
	}

	if value, ok := result["tty"]; ok {
		syscall.Tty = value
	}

	if value, ok := result["per"]; ok {
		syscall.Per = value
	}

	// 64 bit variables, count: 9
	if value, ok := result["sequence"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		syscall.Seq = uint64(v)
	}

	if value, ok := result["timestamp"]; ok {
		v, _ := strconv.ParseFloat(value, 64)
		syscall.Timestamp = float64(v)
	}

	if value, ok := result["arch"]; ok {
		v, _ := strconv.ParseInt(value, 16, 64)
		syscall.Arch = uint64(v)
	}

	if value, ok := result["a0"]; ok {
		v, _ := strconv.ParseInt(value, 16, 64)
		syscall.A0 = uint64(v)
	}

	if value, ok := result["a1"]; ok {
		v, _ := strconv.ParseInt(value, 16, 64)
		syscall.A1 = uint64(v)
	}

	if value, ok := result["a2"]; ok {
		v, _ := strconv.ParseInt(value, 16, 64)
		syscall.A2 = uint64(v)
	}

	if value, ok := result["a3"]; ok {
		v, _ := strconv.ParseInt(value, 16, 64)
		syscall.A3 = uint64(v)
	}

	if value, ok := result["ses"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		syscall.Ses = uint64(v)
	}

	if value, ok := result["items"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		syscall.Items = uint64(v)
	}

	// 32 bit variables, count = 11

	if value, ok := result["ppid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Ppid = uint32(v)
	}

	if value, ok := result["auid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Auid = uint32(v)
	}

	if value, ok := result["uid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Uid = uint32(v)
	}

	if value, ok := result["gid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Gid = uint32(v)
	}

	if value, ok := result["euid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Euid = uint32(v)
	}

	if value, ok := result["suid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Suid = uint32(v)
	}

	if value, ok := result["fsuid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Fsuid = uint32(v)
	}

	if value, ok := result["egid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Egid = uint32(v)
	}

	if value, ok := result["sgid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Sgid = uint32(v)
	}

	if value, ok := result["fsgid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		syscall.Fsgid = uint32(v)
	}

	// 16 bits
	if value, ok := result["syscall"]; ok {
		v, _ := strconv.ParseInt(value, 10, 16)
		syscall.Syscall = uint16(v)
	}

	if value, ok := result["exit"]; ok {
		v, _ := strconv.ParseInt(value, 10, 16)
		syscall.Exit = uint16(v)
	}
	// 1 byte
	if value, ok := result["success"]; ok {
		if value == "yes" {
			syscall.Success = uint8(1)
		} else {
			syscall.Success = uint8(0)
		}
	}
	return true
}

//loads config from config file
func loadConfig(configFile string) (*viper.Viper, error) {
	config := viper.New()
	config.SetConfigFile(configFile)

	if err := config.ReadInConfig(); err != nil {
		return nil, err
	}

	l.SetFlags(config.GetInt("log.flags"))
	el.SetFlags(config.GetInt("log.flags"))

	return config, nil
}

//set audit rules from config
func setRules(config *viper.Viper, e executor) error {
	// Clear existing rules
	if err := e("auditctl", "-D"); err != nil {
		return fmt.Errorf("Failed to flush existing audit rules. Error: %s", err)
	}

	//l.Println("Flushed existing audit rules")

	// Add ours in
	if rules := config.GetStringSlice("rules"); len(rules) != 0 {
		for i, v := range rules {
			// Skip rules with no content
			if v == "" {
				continue
			}

			if err := e("auditctl", strings.Fields(v)...); err != nil {
				return fmt.Errorf("Failed to add rule #%d. Error: %s", i+1, err)
			}

			//l.Printf("Added audit rule #%d\n", i+1)
		}
	} else {
		return errors.New("No audit rules found")
	}

	return nil
}

func SplitAt(substring string) func(data []byte, atEOF bool) (advance int, token []byte, err error) {
	searchBytes := []byte(substring)
	searchLen := len(searchBytes)
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		dataLen := len(data)

		// Return nothing if at end of file and no data passed
		if atEOF && dataLen == 0 {
			return 0, nil, nil
		}

		// Find next separator and return token
		if i := bytes.Index(data, searchBytes); i >= 0 {
			return i + searchLen, data[0:i], nil
		}

		// If we're at EOF, we have a final, non-terminated line. Return it.
		if atEOF {
			return dataLen, data, nil
		}

		// Request more data.
		return 0, nil, nil
	}
}
