package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
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

var l = log.New(os.Stdout, "", 0)   //logging to stdout
var el = log.New(os.Stderr, "", 0)  //logging to stderr
var pid = strconv.Itoa(os.Getpid()) //getting current pid for filtering of collector as well as any children

//regex with named fields that allow the parsing of syscall audit messages (1300)
var regex = regexp.MustCompile(`audit.(?P<timestamp>.*):(?P<sequence>.*).: arch=(?P<arch>.*) syscall=(?P<syscall>\d+)\s*(?:per=(?P<per>.*))?\s*(?:success=(?P<success>.*) exit=(?P<exit>.*))?\s*a0=(?P<a0>.*) a1=(?P<a1>.*) a2=(?P<a2>.*) a3=(?P<a3>.*) items=(?P<items>.*) ppid=(?P<ppid>.*) pid=(?P<pid>.*) auid=(?P<auid>.*) uid=(?P<uid>.*) gid=(?P<gid>.*) euid=(?P<euid>.*) suid=(?P<suid>.*) fsuid=(?P<fsuid>.*) egid=(?P<egid>.*) sgid=(?P<sgid>.*) fsgid=(?P<fsgid>.*) tty=(?P<tty>.*) ses=(?P<ses>.*) comm=(?P<comm>.*) exe=(?P<exe>".*")\s*(?:subj=(?P<subj>.*))?\s*key=(?P<key>.*)`)
var network = getNetwork()

//Struct to represent a singular interface
type Interface struct {
	Iface    string    `json:"iface"`
	Networks []Network `json:"network_data"`
}

//Struct that represents a singular ip and mac on a given interface
type Network struct {
	Ip  string `json:"ip"`
	Mac string `json:"mac"`
}

//All fields in any given syscall audit message
type Syscall struct {
	Network   []Interface `json:"interfaces"`
	Seq       string      `json:"sequence"`
	Timestamp string      `json:"timestamp"`
	Arch      string      `json:"arch"`
	Syscall   string      `json:"syscall"`
	Success   string      `json:"success"`
	Exit      string      `json:"exit"`
	A0        string      `json:"a0"`
	A1        string      `json:"a1"`
	A2        string      `json:"a2"`
	A3        string      `json:"a3"`
	Items     string      `json:"items"`
	Ppid      string      `json:"ppid"`
	Pid       string      `json:"pid"`
	Auid      string      `json:"auid"`
	Uid       string      `json:"uid"`
	Gid       string      `json:"gid"`
	Euid      string      `json:"euid"`
	Suid      string      `json:"suid"`
	Fsuid     string      `json:"fsuid"`
	Egid      string      `json:"egid"`
	Sgid      string      `json:"sgid"`
	Fsgid     string      `json:"fsgid"`
	Tty       string      `json:"tty"`
	Ses       string      `json:"ses"`
	Comm      string      `json:"comm"`
	Exe       string      `json:"exe"`
	Subj      string      `json:"subj"`
	Key       string      `json:"key"`
	Per       string      `json:"per"`
}

//typedef for exec function with variable args
type executor func(string, ...string) error

//execs given program i.e lExec("rm", "-rf", "/")
func lExec(s string, a ...string) error {
	return exec.Command(s, a...).Run()
}

func main() {
	//gets config file location from from commandline input
	configFile := flag.String("config", "", "Config file location")

	flag.Parse()

	if *configFile == "" {
		el.Println("A config file must be provided")
		flag.Usage()
		os.Exit(1)
	}

	//sets up a viper object with the config file provided
	config, err := loadConfig(*configFile)
	if err != nil {
		el.Fatal(err)
	}

	//sets up audit rules according to the config file
	if err := setRules(config, lExec); err != nil {
		el.Fatal(err)
	}

	//init rabbit client
	rabbit, err := createRabbitOutput(config)

	if err != nil {
		el.Fatal(err)
	}

	//gets current time for ausearch purposes (using justins technique for getting syscall data)
	t := time.Now()

	for {
		//uses ausearch to get syscalls since last time t. time formatting is go's way of having custom time formats (the numbers mean things)
		cmd := exec.Command("ausearch", "--raw", "--start", t.Format("01/02/2006"), t.Format("15:04:05"))
		t = time.Now()
		//get stdout pipe from command ran to parse through
		stdout, _ := cmd.StdoutPipe()

		cmd.Start()

		//uses stdout from ausearch command as a buffered scanner
		scanner := bufio.NewScanner(stdout)

		//split by new line to get each syscall
		scanner.Split(SplitAt("\n"))

		for scanner.Scan() {
			//get each line as bytes
			m := scanner.Bytes()

			//there are 2 different message types for 1300. The one we care about starts with type=SYSCALL
			if bytes.HasPrefix(m, []byte("type=SYSCALL")) {
				//print(string(m))
				var sys Syscall

				//attach network data to each message
				sys.Network = network

				good := parseSyscall(&sys, m)

				//filters out any syscall that has the collectors
				if pid != sys.Pid && pid != sys.Ppid {

					err = rabbit.Write(good)

					//error handling for write, if a write fails we'll try to reconnect to rabbit
					if err != nil {
						for {
							if err != nil {
								println("Reconnecting RabbitMQ")
								rabbit, err = createRabbitOutput(config)
							} else {
								break
							}

						}
					}
				}
			}
		}

		cmd.Wait()
	}
}

//gets interface names, ips, and macs
func getNetwork() []Interface {
	addrs, _ := net.Interfaces()
	network := make([]Interface, 0)

	for _, addr := range addrs { //iterate over interfaces
		add, _ := addr.Addrs()
		local := false
		ip_macs := make([]Network, 0)

		for _, add := range add { //iterate over ips on an interface
			if ipnet, ok := add.(*net.IPNet); ok && !ipnet.IP.IsLoopback() { //make sure we dont have a loopback address
				ip_macs = append(ip_macs, Network{
					Mac: addr.HardwareAddr.String(),
					Ip:  add.String(),
				})
			} else {
				local = true
			}
		}

		if local == false { //only add interface if its not local
			network = append(network, Interface{
				Iface:    addr.Name,
				Networks: ip_macs,
			})
		}
	}

	return network
}

func parseSyscall(syscall *Syscall, m []byte) []byte { //parses syscalls using regex

	match := regex.FindStringSubmatch(string(m))
	result := make(map[string]string)

	for i, name := range regex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i] //regex names to map
		}
	}

	// SEND STRINGS
	buf.Reset()
	if value, ok := result["comm"]; ok {
		writeString(value)
	}

	if value, ok := result["exe"]; ok {
		writeString(value)
	}

	if value, ok := result["subj"]; ok {
		writeString(value)
	} else {
		writeString("")
	}

	if value, ok := result["key"]; ok {
		writeString(value)
	}
	if value, ok := result["tty"]; ok {
		writeString(value)
	}
	if value, ok := result["per"]; ok {
		writeString(value)
	}

	// 64 bit variables
	if value, ok := result["sequence"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["timestamp"]; ok {
		v, _ := strconv.ParseFloat(value, 64)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["arch"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["a0"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["a1"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["a2"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["a3"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["ses"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["items"]; ok {
		v, _ := strconv.ParseInt(value, 10, 64)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	// 32 bit variables

	if value, ok := result["ppid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["pid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["auid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["uid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["gid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["euid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["suid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["fsuid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["egid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["sgid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["fsgid"]; ok {
		v, _ := strconv.ParseInt(value, 10, 32)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	// 16 bits
	if value, ok := result["syscall"]; ok {
		v, _ := strconv.ParseInt(value, 10, 16)
		binary.Write(&buf, binary.LittleEndian, v)
	}

	if value, ok := result["exit"]; ok {
		v, _ := strconv.ParseInt(value, 10, 16)
		binary.Write(&buf, binary.LittleEndian, v)
	} else {
		binary.Write(&buf, binary.LittleEndian, 0)
	}
	// 1 byte
	if value, ok := result["success"]; ok {
		if value == "yes" {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
	} else {
		buf.WriteByte(0)
	}

	// write network information last lol

	// write # of Interfaces
	buf.WriteByte(byte(len(syscall.Network)))

	// iterate through network for each iface
	for _, iface := range syscall.Network {

		// write interface name
		writeString(iface.Iface)

		// write number of networks
		buf.WriteByte(byte(len(iface.Networks)))

		for _, network := range iface.Networks {
			// write network's ip
			writeString(network.Ip)
			// write network's mac
			writeString(network.Mac)

		}
	}

	//fmt.Println(string(buf.Bytes()))
	return buf.Bytes()
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

	l.Println("Flushed existing audit rules")

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

			l.Printf("Added audit rule #%d\n", i+1)
		}
	} else {
		return errors.New("No audit rules found")
	}

	return nil
}

//used to split the input string by newlines
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
