package main

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDER(t *testing.T) {
	got, err := parseDER("testdata/google-com.der")
	if err != nil {
		t.Fatalf("parseDER: %v", err)
	}
	if !strings.Contains(got, "OBJECT IDENTIFIER: sha256WithRSAEncryption") {
		t.Errorf("output lacks the signature algorithm:\n%s", got)
	}
}

func TestParseDERErrors(t *testing.T) {
	dir := t.TempDir()
	truncated := filepath.Join(dir, "truncated.der")
	if err := os.WriteFile(truncated, []byte{0x30, 0x05, 0x02, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		path   string
		wantIs error
		prefix string
	}{
		{"missing file", filepath.Join(dir, "missing.der"), os.ErrNotExist, "reading file: "},
		{"truncated DER", truncated, nil, "parsing ASN.1 data: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDER(tt.path)
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

func TestParseASN1(t *testing.T) {
	tests := []struct {
		name    string
		der     string // hex
		want    string
		wantErr bool
	}{
		{"context primitive", "86026162", "[6]: 6162\n", false},
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
			err = parseASN1(der, "", &got)
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
