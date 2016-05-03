// This file uses code from http://golang.org/src/log/log.go
// modified for JSON logging
//
// Copyright (c) 2012 The Go Authors. All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:

//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package log

// These tests are too simple.

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

const (
	Rdate         = `[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]`
	Rtime         = `[0-9][0-9]:[0-9][0-9]:[0-9][0-9]`
	Rmicroseconds = `\.[0-9][0-9][0-9][0-9][0-9][0-9]`
	Rline         = `(83|85):` // must update if the calls to l.Printf / l.Print below move
	Rlongfile     = `.*/[A-Za-z0-9_\-]+\.go:` + Rline
	Rshortfile    = `[A-Za-z0-9_\-]+\.go:` + Rline
)

type tester struct {
	flag    int
	prefix  string
	pattern string // regexp that log output must match; we add ^ and expected_text$ always
}

var tests = []tester{
	// individual pieces:
	{0, "", ""},
	{0, "XXX", "XXX"},
	{Ldate, "", Rdate + " "},
	{Ltime, "", Rtime + " "},
	{Ltime | Lmicroseconds, "", Rtime + Rmicroseconds + " "},
	{Lmicroseconds, "", Rtime + Rmicroseconds + " "}, // microsec implies time
	{Llongfile, "", Rlongfile + " "},
	{Lshortfile, "", Rshortfile + " "},
	{Llongfile | Lshortfile, "", Rshortfile + " "}, // shortfile overrides longfile
	// everything at once:
	{Ldate | Ltime | Lmicroseconds | Llongfile, "XXX", "XXX" + Rdate + " " + Rtime + Rmicroseconds + " " + Rlongfile + " "},
	{Ldate | Ltime | Lmicroseconds | Lshortfile, "XXX", "XXX" + Rdate + " " + Rtime + Rmicroseconds + " " + Rshortfile + " "},
}

// Test using Println("hello", 23, "world") or using Printf("hello %d world", 23)
func testPrint(t *testing.T, flag int, prefix string, pattern string, useFormat bool) {
	var m LogMessage
	buf := new(bytes.Buffer)
	SetOutput(buf)
	SetFlags(flag)
	SetPrefix(prefix)
	if useFormat {
		Printf("hello %d world\n", 23)
	} else {
		Println("hello", 23, "world")
	}
	pattern = "^" + pattern + "hello 23 world\n$"
	err := json.NewDecoder(buf).Decode(&m)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}
	if m.ID == "" {
		t.Errorf("ID should be set to random value and not empty")
	}
	payload, ok := m.Payload.(string)
	if !ok {
		t.Errorf("Payload is not of string type")
	}
	matched, err4 := regexp.MatchString(pattern, payload)
	if err4 != nil {
		t.Fatal("pattern did not compile:", err4)
	}
	if !matched {
		t.Errorf("log output should match %q is %q", pattern, payload)
	}
	SetOutput(os.Stderr)
}

func TestAll(t *testing.T) {
	for _, testcase := range tests {
		testPrint(t, testcase.flag, testcase.prefix, testcase.pattern, false)
		testPrint(t, testcase.flag, testcase.prefix, testcase.pattern, true)
	}
}

func TestOutput(t *testing.T) {
	const testString = "test"
	var b bytes.Buffer
	var m LogMessage
	l := New(&b, "", 0)
	l.Print(testString)
	err := json.NewDecoder(&b).Decode(&m)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}
	if m.ID == "" {
		t.Errorf("ID should be set to random value and not empty")
	}
	payload, ok := m.Payload.(string)
	if !ok {
		t.Errorf("Payload is not of string type")
	}

	if expect := testString; payload != expect {
		t.Errorf("log output should match %q is %q", expect, payload)
	}
}

func TestIDUnique(t *testing.T) {
	const testString = "test"
	var b bytes.Buffer
	var m1 LogMessage
	var m2 LogMessage
	l := New(&b, "", 0)
	l.Print(testString)
	decoder := json.NewDecoder(&b)
	err := decoder.Decode(&m1)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}

	l.Print(testString)
	err = decoder.Decode(&m2)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}
	if m1.ID == m2.ID {
		t.Errorf("ID should be set to random value and not equal: %q == %q", m1.ID, m2.ID)
	}
}

func TestHostSet(t *testing.T) {
	const testString = "test"
	var b bytes.Buffer
	var m LogMessage
	l := New(&b, "", 0)
	l.Print(testString)
	err := json.NewDecoder(&b).Decode(&m)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}
}

func TestVersionSet(t *testing.T) {
	const testString = "test"
	var b bytes.Buffer
	var m LogMessage
	l := New(&b, "", 0)
	l.SetVersion("version-secret_panda")
	l.Print(testString)
	err := json.NewDecoder(&b).Decode(&m)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}
	if m.Version != "version-secret_panda" {
		t.Errorf("Expected service name to be version-secret_panda, got %q", m.Version)
	}
}

func TestServiceSet(t *testing.T) {
	const testString = "test"
	var b bytes.Buffer
	var m LogMessage
	l := New(&b, "", 0)
	l.SetService("codename-secret_panda")
	l.Print(testString)
	err := json.NewDecoder(&b).Decode(&m)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}
	if m.Service != "codename-secret_panda" {
		t.Errorf("Expected service name to be codename-secret_panda, got %q", m.Service)
	}
}

func TestOutputJSON(t *testing.T) {
	data := struct {
		Title  string
		Number int
	}{
		"Whoa metrics",
		1337,
	}
	var m LogMessage
	var b bytes.Buffer
	l := New(&b, "", LstdFlags)
	l.OutputJSON(data)
	d := struct {
		Title  string
		Number int
	}{}
	m.Payload = &d
	err := json.NewDecoder(&b).Decode(&m)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}
	if d.Title != "Whoa metrics" {
		t.Errorf("Expected Title to be Whoa metrics, got %q", d.Title)
	}
	if d.Number != 1337 {
		t.Errorf("Expected Number to be 1337, got %d", d.Number)
	}
}

func TestOutputBinary(t *testing.T) {
	var m LogMessage
	var b bytes.Buffer
	l := New(&b, "", LstdFlags)
	l.OutputBinary([]byte(""))
	err := json.NewDecoder(&b).Decode(&m)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}
}

func TestFlagAndPrefixSetting(t *testing.T) {
	var m LogMessage
	var b bytes.Buffer
	l := New(&b, "Test:", LstdFlags)
	f := l.Flags()
	if f != LstdFlags {
		t.Errorf("Flags 1: expected %x got %x", LstdFlags, f)
	}
	l.SetFlags(f | Lmicroseconds)
	f = l.Flags()
	if f != LstdFlags|Lmicroseconds {
		t.Errorf("Flags 2: expected %x got %x", LstdFlags|Lmicroseconds, f)
	}
	p := l.Prefix()
	if p != "Test:" {
		t.Errorf(`Prefix: expected "Test:" got %q`, p)
	}
	l.SetPrefix("Reality:")
	p = l.Prefix()
	if p != "Reality:" {
		t.Errorf(`Prefix: expected "Reality:" got %q`, p)
	}
	// Verify a log message looks right, with our prefix and microseconds present.
	l.Print("hello")
	pattern := "^Reality:" + Rdate + " " + Rtime + Rmicroseconds + " hello"
	err := json.NewDecoder(&b).Decode(&m)
	if err != nil {
		t.Errorf("Unexpected error decoding log JSON: %q", err.Error())
	}
	payload, ok := m.Payload.(string)
	if !ok {
		t.Errorf("Payload is not of string type")
	}
	matched, err := regexp.Match(pattern, []byte(payload))
	if err != nil {
		t.Fatalf("pattern %q did not compile: %s", pattern, err)
	}
	if !matched {
		t.Errorf("message did not match pattern %q is %q", pattern, payload)
	}
}
