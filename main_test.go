package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	derData, err := os.ReadFile("testdata/google-com.der")
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := os.ReadFile("testdata/google-com.pem")
	if err != nil {
		t.Fatal(err)
	}
	want, err := run("testdata/google-com.der", formatDER, options{}, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(want, "OBJECT IDENTIFIER: sha256WithRSAEncryption") {
		t.Errorf("output lacks the signature algorithm:\n%s", want)
	}

	tests := []struct {
		name   string
		path   string
		format inputFormat
		stdin  []byte
	}{
		{"PEM file", "testdata/google-com.pem", formatPEM, nil},
		{"DER on stdin", "-", formatDER, derData},
		{"PEM on stdin", "-", formatPEM, pemData},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := run(tt.path, tt.format, options{}, bytes.NewReader(tt.stdin))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if got != want {
				t.Errorf("output differs from the DER file output")
			}
		})
	}
}

func TestRunErrors(t *testing.T) {
	dir := t.TempDir()
	truncated := filepath.Join(dir, "truncated.der")
	if err := os.WriteFile(truncated, []byte{0x30, 0x05, 0x02, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		path   string
		format inputFormat
		wantIs error
		prefix string
	}{
		{"missing file", filepath.Join(dir, "missing.der"), formatDER, os.ErrNotExist, "reading input: "},
		{"truncated DER", truncated, formatDER, nil, "parsing ASN.1 data: "},
		{"DER read as PEM", "testdata/google-com.der", formatPEM, nil, "decoding PEM: "},
		{"PEM read as DER", "testdata/google-com.pem", formatDER, nil, "parsing ASN.1 data: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(tt.path, tt.format, options{}, nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.HasPrefix(err.Error(), tt.prefix) {
				t.Errorf("error %q lacks prefix %q", err, tt.prefix)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("errors.Is(%v, %v) = false", err, tt.wantIs)
			}
		})
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		in      string
		want    inputFormat
		wantErr bool
	}{
		{"DER", formatDER, false},
		{"der", formatDER, false},
		{"PEM", formatPEM, false},
		{"pem", formatPEM, false},
		{"XYZ", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := parseFormat(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("parseFormat(%q) = %v, %v; want %v, wantErr %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestParseASN1(t *testing.T) {
	tests := []struct {
		name    string
		der     string // hex
		want    string
		wantErr bool
	}{
		{"context primitive printable", "86026162", "[6]: \"ab\"\n", false},
		{"context primitive printable quotes", "860322615c", "[6]: \"\\\"a\\\\\"\n", false},
		{"context primitive binary", "80020aff", "[0]: 0aff\n", false},
		{"context primitive empty", "8000", "[0]: \n", false},
		{"context constructed", "a003020102", "[0]\n  INTEGER: 02\n", false},
		{"application tag", "4100", "[APPLICATION 1]: \n", false},
		{"octet string with nested DER", "0403020105", "OCTET STRING\n  INTEGER: 05\n", false},
		{"octet string partially DER falls back to hex", "04050201050205", "OCTET STRING: 0201050205\n", false},
		{"empty octet string", "0400", "OCTET STRING: \n", false},
		{"bit string with unused bits", "03020780", "BIT STRING (7 unused bits): 80\n", false},
		{"bit string with nested DER", "030400020105", "BIT STRING (0 unused bits)\n  INTEGER: 05\n", false},
		{"invalid bit string", "030108", "", true},
		{"UTCTime", "170d3235303730373038333430335a", "UTCTime: 250707083403Z (2025-07-07T08:34:03Z)\n", false},
		{"GeneralizedTime", "180f32303235303730373038333430335a", "GeneralizedTime: 20250707083403Z (2025-07-07T08:34:03Z)\n", false},
		{"IA5String", "1603612e62", "IA5String: a.b\n", false},
		{"non-printable UTF8String", "0c0107", "UTF8String: 07\n", false},
		{"BMPString", "1e0400480069", "BMPString: Hi\n", false},
		{"sibling values", "020101020102", "INTEGER: 01\nINTEGER: 02\n", false},
		{"truncated sibling", "0201010500ff", "", true},
		{"truncated sequence", "30050201", "", true},
		{"OID", "06032a0304", "OBJECT IDENTIFIER: 1.2.3.4\n", false},
		{"empty OID", "0600", "", true},
		{"invalid OID inside octet string falls back to hex", "04020600", "OCTET STRING: 0600\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := hex.DecodeString(tt.der)
			if err != nil {
				t.Fatal(err)
			}
			var got string
			err = parseASN1(der, 0, 0, options{}, &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetOIDName(t *testing.T) {
	tests := []struct {
		oid  string
		want string
	}{
		{"1.2.840.113549.1.1.10", "RSASSA-PSS"},
		{"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
		{"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
		{"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
		{"1.2.840.113549.1.1.14", "sha224WithRSAEncryption"},
		{"1.2.840.113549.1.5.14", "pkcs5-PBMAC1"},
		{"1.2.840.113549.1.12.10.1.3", "pkcs-12-certBag"},
		{"2.5.29.29", "certificateIssuer"},
		{"2.5.29.55", "targetInformation"},
		{"1.2.840.10045.2.1", "id-ecPublicKey"},
		{"1.3.6.1.5.5.7.3.1", "serverAuth"},
		{"1.2.3.4", "1.2.3.4"}, // unknown OIDs are returned unchanged
	}
	for _, tt := range tests {
		if got := getOIDName(tt.oid); got != tt.want {
			t.Errorf("getOIDName(%q) = %q, want %q", tt.oid, got, tt.want)
		}
	}
}

func TestParseASN1Offsets(t *testing.T) {
	// SEQUENCE { OCTET STRING { INTEGER 5 }, BIT STRING { INTEGER 5 } }
	der, err := hex.DecodeString("300b0403020105030400020105")
	if err != nil {
		t.Fatal(err)
	}
	want := "" +
		"    0:d=0  hl=2 l=  11 SEQUENCE\n" +
		"    2:d=1  hl=2 l=   3   OCTET STRING\n" +
		"    4:d=2  hl=2 l=   1     INTEGER: 05\n" +
		"    7:d=1  hl=2 l=   4   BIT STRING (0 unused bits)\n" +
		"   10:d=2  hl=2 l=   1     INTEGER: 05\n" // after the unused-bits byte
	var got string
	if err := parseASN1(der, 0, 0, options{offsets: true}, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}
