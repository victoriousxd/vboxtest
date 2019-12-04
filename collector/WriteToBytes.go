package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
)

var buf bytes.Buffer
var allFields = []string{"Arch", "Syscall", "Success", "Exit", "A0", "A1", "A2", "A3", "Items", "Ppid", "Pid", "Auid", "Uid", "Gid", "Euid", "Suid", "Fsuid", "Egid", "Sgid", "Fsgid", "Tty", "Ses", "Comm", "Exe", "Subj", "Key"}
var power = true

/*

Functions to convert a syscall to bytes. Demo can be found here
https://repl.it/@VictoriaHong/KeyFantasticInitialization


// user defined wants list
var wanted = []string{"Arch", "Syscall", "Success", "Exit", "A0", "A1", "A2", "A3", "Items", "Ppid", "Pid", "Auid", "Uid", "Gid", "Euid", "Suid", "Fsuid", "Egid", "Sgid", "Fsgid", "Tty", "Ses", "Comm", "Exe", "Subj", "Key"}

var stringTypes = []string{"Iface", "Ip", "MAC", "TimeStamp", "Comm", "Exe",
"Subj", "Key", "Tty"}



// types represented by 1 byte
var byteTypes = []string{"success"}
var int16Types = []string{"exit","syscall"}
// types represented by short
var int32Types = []string{"Ppid", "Pid", "Auid", "Uid", "Gid", "Euid", "Suid", "Fsuid", "Egid", "Sgid", "Fsgid"}

// 64 bit byte strings
var int64Types = []string{ "A0", "A1", "A2", "A3", "Items" }

var emptyValues = []string{"", "(none)"}

func markPresent(yeet sysCallInfo, i int , valueName string, value []byte){

}
*/

//var present = make([]bytes,3)

// takes a sysCall structs and converts each section to bytes
// returns a byte array / []bytes
func iterateStruct(sc Syscall) bytes.Buffer {
	t := reflect.TypeOf(sc)
	v := reflect.ValueOf(sc)
	buf.Reset()
	// write network information first
	// write # of Interfaces
	buf.WriteByte(byte(len(sc.Network)))

	// iterate through network for each iface
	for _, iface := range sc.Network {

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

	// terminate network bytes with a '0'

	for i := 1; i < v.NumField(); i++ {
		vType := t.Field(i).Name
		val := v.Field(i).Interface().(string)

		switch vType {
		case "Comm", "Exe",
			"Subj", "Key", "Tty":
			writeString(val)
			continue
		case "success":
			if val == "yes" {
				buf.WriteByte(1)
			} else {
				buf.WriteByte(1)
			}
			continue

		case "A0", "A1", "A2", "A3", "Items":
			v, _ := strconv.ParseInt(val, 10, 64)
			binary.Write(&buf, binary.LittleEndian, v)
		case "exit", "Syscall":
			v, _ := strconv.Atoi(val)
			binary.Write(&buf, binary.LittleEndian, v)
		case "TimeStamp":
			v, _ := strconv.ParseFloat(val, 64)
			binary.Write(&buf, binary.LittleEndian, v)
		default:
			v, _ := strconv.ParseInt(val, 10, 32)
			binary.Write(&buf, binary.LittleEndian, v)

		}

	}
	return buf
}

// string format = string length + string + '/00'
func writeString(s string) {
	binary.Write(&buf, binary.LittleEndian, uint16(len(s)))
	buf.Write([]byte(s))
}

func GracefulExit() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		power = false
	}()
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
