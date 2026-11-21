package main

import "testing"

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
