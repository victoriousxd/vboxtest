package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"
)

var power = true

var filterSelf = false
var follow = false
var found = false
var timesUp = false

var buf bytes.Buffer

//var allFields = []string{"Arch", "Syscall", "Success", "Exit", "A0", "A1", "A2", "A3", "Items", "Ppid", "Pid", "Auid", "Uid", "Gid", "Euid", "Suid", "Fsuid", "Egid", "Sgid", "Fsgid", "Tty", "Ses", "Comm", "Exe", "Subj", "Key"}

var comm = "screen"
var listOfPids = make([]int64, 0)
var commList = make([]string, 0)

func GracefulExitHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fmt.Println("\nRecording interrupted.\n")
		os.Exit(0)
	}()
}

func setUpTimer(arg time.Duration) {
	fmt.Printf("Timer set for %v\n", arg)
	time.AfterFunc(arg, func() {
		fmt.Println("\nTimer is up.\n")
		os.Exit(0)
	})
}

func lost(s []byte) {
	fmt.Println(s)
}

// follow and add to pids and comms, return true on success
func followComm(sysComm string, sysPid int64) bool {
	if (strings.HasPrefix(sysComm, comm) || sysComm == comm) && !containsInt(listOfPids, sysPid) {
		if !found {
			commList = append(commList, sysComm)
			found = true
		}
		fmt.Println("\v - \v", sysComm, sysPid)
		listOfPids = append(listOfPids, sysPid)
		return true
	} else {
		return addCommList(sysComm, sysPid)
	}
}

// follow comms
func addCommList(sysComm string, sysPid int64) bool {
	if !containsString(commList, sysComm) {
		//fmt.Println("FOUND: \v - \v", sysComm, sysPid)
		commList = append(commList, sysComm)
		return true
	}
	return false
}

// string format = string length + string + '/00'
func writeString(s string) {
	binary.Write(&buf, binary.LittleEndian, uint16(len(s)))
	buf.Write([]byte(s))
}

func containsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
func containsInt(s []int64, e int64) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
