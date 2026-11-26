package sambaacl

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

const testAdmin = "S-1-5-21-1-2-3-512"

func TestPythonSambaNTACLFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/python-ntacl-v1.json")
	if err != nil {
		t.Fatal(err)
	}

	var cases []struct {
		Name   string
		Admin  string
		Levels map[string]int
		Options
		SDDL   string
		Packed string
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 5 {
		t.Fatalf("expected five independent Samba fixtures, got %d", len(cases))
	}

	for _, fixture := range cases {
		t.Run(fixture.Name, func(t *testing.T) {
			descriptor, err := NewDescriptor(fixture.Levels, fixture.Admin, fixture.Options)
			if err != nil {
				t.Fatal(err)
			}
			if got := descriptor.SDDL(); got != fixture.SDDL {
				t.Fatalf("SDDL differs from Python\ngot:  %s\nwant: %s", got, fixture.SDDL)
			}

			previous, err := hex.DecodeString(fixture.Packed)
			if err != nil {
				t.Fatal(err)
			}
			native, err := descriptor.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(native, previous) {
				t.Fatalf("NTACL differs from Samba\ngot:  %x\nwant: %x", native, previous)
			}
		})
	}
}

func TestInvalidDescriptorArguments(t *testing.T) {
	for _, tc := range []struct {
		name   string
		admin  string
		levels map[string]int
		opt    Options
	}{
		{name: "no admin"},
		{name: "invalid level", admin: testAdmin, levels: map[string]int{testAdmin: 4}},
		{name: "invalid hidden SID", admin: testAdmin, levels: map[string]int{"malformed": 0}},
		{name: "overflowing SID", admin: "S-1-5-21-1-2-3-4294967296"},
		{name: "signed SID", admin: "S-1-5-21-1-2-3-+512"},
		{name: "inherit from file", admin: testAdmin, opt: Options{TopLevel: true}},
		{name: "share-root assignments", admin: testAdmin, opt: Options{Directory: true, ShareRoot: true}, levels: map[string]int{testAdmin: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDescriptor(tc.levels, tc.admin, tc.opt)
			if err == nil {
				t.Fatal("accepted invalid ACL input")
			}
		})
	}

	if _, err := (Descriptor{}).Pack(); err == nil {
		t.Fatal("packed an uninitialized descriptor")
	}
}

func TestDACLSizeBound(t *testing.T) {
	levels := make(map[string]int)
	for i := 0; i < 1000; i++ {
		levels[fmt.Sprintf("S-1-5-21-1-2-3-%d", 1000+i)] = 3
	}
	if _, err := NewDescriptor(levels, testAdmin, Options{Directory: true, TopLevel: true}); err == nil {
		t.Fatal("allowed the 16-bit DACL size to overflow")
	}
}
