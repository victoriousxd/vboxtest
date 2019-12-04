package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"time"

)

var l = log.New(os.Stdout, "", 0)
var el = log.New(os.Stderr, "", 0)
var pid = os.Getpid()
var regex = regexp.MustCompile( `audit.(?P<timestamp>.*):(?P<sequence>.*).: arch=(?P<arch>.*) syscall=(?P<syscall>\d+) (?:success=(?P<success>.*) exit=(?P<exit>.*))?[ ]*a0=(?P<a0>.*) a1=(?P<a1>.*) a2=(?P<a2>.*) a3=(?P<a3>.*) items=(?P<items>.*) ppid=(?P<ppid>.*) pid=(?P<pid>.*) auid=(?P<auid>.*) uid=(?P<uid>.*) gid=(?P<gid>.*) euid=(?P<euid>.*) suid=(?P<suid>.*) fsuid=(?P<fsuid>.*) egid=(?P<egid>.*) sgid=(?P<sgid>.*) fsgid=(?P<fsgid>.*) tty=(?P<tty>.*) ses=(?P<ses>.*) comm=(?P<comm>.*) exe=(?P<exe>.*)[ ]*(?:subj=(?P<subj>.*))? key=(?P<key>.*)`)
var network = getNetork()

var found = false
var comm = "Virus"
var listofPids = make([]string,0)


type Interface struct {
	Iface string `json:"iface"`
	Networks []Network `json:"network_data"`
}

type Network struct {
	Ip string `json:"ip"`
	Mac string `json:"mac"`
}


type Syscall struct {
	Network 	  []Interface 		`json:"interfaces"`
	Seq           string               `json:"sequence"`
	Timestamp     string            `json:"timestamp"`
	Arch		  string 			`json:"arch"`
	Syscall       string            `json:"syscall"`
	Success	      string			`json:"success"`
	Exit	      string				`json:"exit"`
	A0			  string			`json:"a0"`
	A1			  string			`json:"a1"`
	A2			  string			`json:"a2"`
	A3			  string			`json:"a3"`
	Items		  string			`json:"items"`
	Ppid		  string				`json:"ppid"`
	Pid			  string				`json:"pid"`
	Auid          string	            `json:"auid"`
	Uid       	  string	            `json:"uid"`
	Gid           string       	    `json:"gid"`
	Euid          string   	        `json:"euid"`
	Suid          string	            `json:"suid"`
	Fsuid         string               `json:"fsuid"`
	Egid          string               `json:"egid"`
	Sgid          string               `json:"sgid"`
	Fsgid         string               `json:"fsgid"`
	Tty           string               `json:"tty"`
	Ses           string            `json:"ses"`
	Comm          string            `json:"comm"`
	Exe           string            `json:"exe"`
	Subj          string            `json:"subj"`
	Key           string            `json:"key"`
}

type executor func(string, ...string) error

func lExec(s string, a ...string) error {
	return exec.Command(s, a...).Run()
}

func main() {
	if err := setRules(lExec); err != nil {
		el.Fatal(err)
	}


	t := time.Now()

	for {

		cmd := exec.Command("ausearch","--raw", "--start",t.Format("01/02/2006"),t.Format("15:04:05"))
		t = time.Now()
		stdout, _ := cmd.StdoutPipe()

		cmd.Start()

		scanner := bufio.NewScanner(stdout)
		scanner.Split(SplitAt("\n"))
		for scanner.Scan() {
			m := scanner.Bytes()

			if bytes.HasPrefix(m, []byte("type=SYSCALL")) {
				//print(string(m))
				var sys Syscall

				sys.Network = network
				
				err := parseSyscall(&sys, m)

				if err != nil{
					continue
				}

				jsn, err := json.Marshal(sys)

				if err == nil{
					fmt.Println(string(jsn))
					// start conditionals here
					// compare comm, check if it starts with [...]
					// find f=pid that spawned unique virus if bool == found
					// ppid = pid 
					// if pid doesnt show up as ppid for 20 seconds
					//lets assume its done :) 

				}
			}
		}

		cmd.Wait()
	}
}


func getNetork() ([]Interface) {
	addrs, _ := net.Interfaces()
	network := make([]Interface,0)

	for _, addr := range addrs {
		 add, _ :=  addr.Addrs()

		 ip_macs := make([]Network,0)
		 for _, add := range add{
			 ip_macs = append(ip_macs, Network{
				 Mac: addr.HardwareAddr.String(),
				 Ip:  add.String(),
			 })
		 }

		network = append(network,Interface{
			Iface:    addr.Name,
			Networks: ip_macs,
		} )
	}

	return network
}

func parseSyscall(syscall *Syscall, m []byte) (error) {

	match := regex.FindStringSubmatch(string(m))
	result := make(map[string]string)

	for i, name := range regex.SubexpNames() {
		if i != 0 && name != ""{
			result[name] = match[i]
		}
	}

	if value,ok := result["sequence"]; ok {
		syscall.Seq = value
	}


	if value,ok := result["timestamp"]; ok {
		syscall.Timestamp = value
	}


	if value,ok := result["arch"]; ok {
		syscall.Arch = value
	}


	if value,ok := result["syscall"]; ok {
		syscall.Syscall = value
	}


	if value,ok := result["success"]; ok {
		syscall.Success = value
	}else{
		syscall.Success = ""
	}


	if value,ok := result["exit"]; ok {
		syscall.Exit = value
	}else{
		syscall.Exit = ""
	}


	if value,ok := result["a0"]; ok {
		syscall.A0 = value
	}


	if value,ok := result["a1"]; ok {
		syscall.A1 = value
	}


	if value,ok := result["a2"]; ok {
		syscall.A2 = value
	}


	if value,ok := result["a3"]; ok {
		syscall.A3 = value
	}


	if value,ok := result["items"]; ok {
		syscall.Items = value
	}


	if value,ok := result["ppid"]; ok {
		syscall.Ppid = value
	}


	if value,ok := result["pid"]; ok {
		syscall.Pid = value
	}


	if value,ok := result["auid"]; ok {
		syscall.Auid = value
	}


	if value,ok := result["uid"]; ok {
		syscall.Uid = value
	}


	if value,ok := result["gid"]; ok {
		syscall.Gid = value
	}


	if value,ok := result["euid"]; ok {
		syscall.Euid = value
	}


	if value,ok := result["suid"]; ok {
		syscall.Suid = value
	}


	if value,ok := result["fsuid"]; ok {
		syscall.Fsuid = value
	}


	if value,ok := result["egid"]; ok {
		syscall.Egid = value
	}


	if value,ok := result["sgid"]; ok {
		syscall.Sgid = value
	}


	if value,ok := result["fsgid"]; ok {
		syscall.Fsgid = value
	}


	if value,ok := result["tty"]; ok {
		syscall.Tty = value
	}


	if value,ok := result["ses"]; ok {
		syscall.Ses = value
	}


	if value,ok := result["comm"]; ok {
		syscall.Comm = value
	}


	if value,ok := result["exe"]; ok {
		syscall.Exe = value
	}


	if value,ok := result["subj"]; ok {
		syscall.Subj = value
	}else{
		syscall.Subj = ""
	}


	if value,ok := result["key"]; ok {
		syscall.Key = value
	}

	return nil
}


func setRules( e executor) error {
	// Clear existing rules
	if err := e("auditctl", "-D"); err != nil {
		return fmt.Errorf("Failed to flush existing audit rules. Error: %s", err)
	}

	l.Println("Flushed existing audit rules")


	if err := e("auditctl", "-a","exit,always","-S", "all"); err != nil {
		return fmt.Errorf("Failed to add rule")
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



