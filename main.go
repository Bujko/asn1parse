package main

import (
	"encoding/asn1"
	"flag"
	"fmt"
	"os"
	"time"
	"unicode"
	"unicode/utf8"
)

// oidNames maps dotted OIDs to their conventional names.
var oidNames = map[string]string{
	// X.509
	"2.5.4.3":              "commonName",
	"2.5.4.6":              "countryName",
	"2.5.4.7":              "localityName",
	"2.5.4.8":              "stateOrProvinceName",
	"2.5.4.10":             "organizationName",
	"2.5.4.11":             "organizationalUnitName",
	"2.5.4.5":              "serialNumber",
	"2.5.4.9":              "streetAddress",
	"2.5.4.12":             "title",
	"2.5.4.13":             "description",
	"2.5.4.15":             "businessCategory",
	"2.5.4.17":             "postalCode",
	"2.5.4.20":             "telephoneNumber",
	"2.5.4.41":             "name",
	"2.5.4.42":             "givenName",
	"2.5.4.43":             "initials",
	"2.5.4.44":             "generationQualifier",
	"2.5.4.46":             "dnQualifier",
	"2.5.4.65":             "pseudonym",
	"1.2.840.113549.1.9.1": "emailAddress",
	"2.5.29.14":            "subjectKeyIdentifier",
	"2.5.29.15":            "keyUsage",
	"2.5.29.17":            "subjectAltName",
	"2.5.29.18":            "issuerAltName",
	"2.5.29.19":            "basicConstraints",
	"2.5.29.31":            "cRLDistributionPoints",
	"2.5.29.32":            "certificatePolicies",
	"2.5.29.35":            "authorityKeyIdentifier",
	"2.5.29.37":            "extendedKeyUsage",
	"2.5.29.30":            "nameConstraints",
	"2.5.29.33":            "policyMappings",
	"2.5.29.36":            "policyConstraints",
	"2.5.29.54":            "inhibitAnyPolicy",
	"2.5.29.46":            "freshestCRL",
	"2.5.29.20":            "cRLNumber",
	"2.5.29.21":            "reasonCode",
	"2.5.29.27":            "deltaCRLIndicator",
	"2.5.29.28":            "issuingDistributionPoint",
	"2.5.29.23":            "holdInstructionCode",
	"2.5.29.24":            "invalidityDate",
	"2.5.29.56":            "noRevAvail",
	"2.5.29.9":             "subjectDirectoryAttributes",
	"2.5.29.16":            "privateKeyUsagePeriod",
	"2.5.29.29":            "certificateIssuer",
	"2.5.29.40":            "cRLStreamIdentifier",
	"2.5.29.55":            "targetInformation",
	"2.5.29.38":            "authorityAttributeIdentifier",
	"2.5.29.39":            "roleSpecCertIdentifier",
	"2.5.29.47":            "orderedList",
	"2.5.29.48":            "attributeDescriptor",
	"2.5.29.49":            "userNotice",
	"2.5.29.50":            "sOAIdentifier",
	"2.5.29.51":            "baseUpdateTime",
	"2.5.29.52":            "acceptableCertPolicies",
	"2.5.29.53":            "deltaInfo",
	// PKIX
	"1.3.6.1.5.5.7.1.1":       "authorityInfoAccess",
	"1.3.6.1.5.5.7.48.1":      "ocsp",
	"1.3.6.1.5.5.7.48.2":      "caIssuers",
	"1.3.6.1.5.5.7.3.1":       "serverAuth",
	"1.3.6.1.5.5.7.3.2":       "clientAuth",
	"1.3.6.1.5.5.7.3.3":       "codeSigning",
	"1.3.6.1.5.5.7.3.4":       "emailProtection",
	"1.3.6.1.5.5.7.3.8":       "timeStamping",
	"1.3.6.1.5.5.7.3.9":       "OCSPSigning",
	"1.3.6.1.4.1.11129.2.4.2": "ctPrecertificateSCTs",
	"2.23.140.1.2.1":          "domain-validated",
	"2.23.140.1.2.2":          "organization-validated",
	// ANSI X9.62
	"1.2.840.10045.2.1":   "id-ecPublicKey",
	"1.2.840.10045.3.1.7": "prime256v1",
	// PKCS1
	"1.2.840.113549.1.1.1":  "rsaEncryption",
	"1.2.840.113549.1.1.2":  "md2WithRSAEncryption",
	"1.2.840.113549.1.1.3":  "md4WithRSAEncryption",
	"1.2.840.113549.1.1.4":  "md5WithRSAEncryption",
	"1.2.840.113549.1.1.5":  "sha1WithRSAEncryption",
	"1.2.840.113549.1.1.6":  "rsaOAEPEncryptionSET",
	"1.2.840.113549.1.1.7":  "id-RSAES-OAEP",
	"1.2.840.113549.1.1.8":  "mgf1",
	"1.2.840.113549.1.1.9":  "id-pSpecified",
	"1.2.840.113549.1.1.10": "RSASSA-PSS",
	"1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
	"1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
	"1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
	"1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
	// PKCS5
	"1.2.840.113549.1.5.1":  "pkcs5-pbeWithMD2AndDES-CBC",
	"1.2.840.113549.1.5.3":  "pkcs5-pbeWithMD5AndDES-CBC",
	"1.2.840.113549.1.5.4":  "pkcs5-pbeWithMD2AndRC2-CBC",
	"1.2.840.113549.1.5.6":  "pkcs5-pbeWithMD5AndRC2-CBC",
	"1.2.840.113549.1.5.10": "pkcs5-pbeWithSHA1AndDES-CBC",
	"1.2.840.113549.1.5.11": "pkcs5-pbeWithSHA1AndRC2-CBC",
	"1.2.840.113549.1.5.12": "pkcs5-PBKDF2",
	"1.2.840.113549.1.5.13": "pkcs5-pbes2",
	"1.2.840.113549.1.5.14": "pkcs5-PBMAC1",
	// PKCS7
	"1.2.840.113549.1.7.1": "pkcs7-data",
	"1.2.840.113549.1.7.2": "pkcs7-signedData",
	"1.2.840.113549.1.7.3": "pkcs7-envelopedData",
	"1.2.840.113549.1.7.4": "pkcs7-signedAndEnvelopedData",
	"1.2.840.113549.1.7.5": "pkcs7-digestedData",
	"1.2.840.113549.1.7.6": "pkcs7-encryptedData",
	// PKCS12
	"1.2.840.113549.1.12.10.1.1": "pkcs-12-keyBag",
	"1.2.840.113549.1.12.10.1.2": "pkcs-12-pkcs8ShroudedKeyBag",
	"1.2.840.113549.1.12.10.1.3": "pkcs-12-certBag",
	"1.2.840.113549.1.12.10.1.4": "pkcs-12-crlBag",
	"1.2.840.113549.1.12.10.1.5": "pkcs-12-secretBag",
	"1.2.840.113549.1.12.10.1.6": "pkcs-12-safeContentsBag",
	"1.2.840.113549.1.12.1.1":    "pkcs-12-PBEID-SHA1And128BitRC4",
	"1.2.840.113549.1.12.1.2":    "pkcs-12-PBEID-SHA1And40BitRC4",
	"1.2.840.113549.1.12.1.3":    "pkcs-12-PBEID-SHA1And3KeyTripleDES-CBC",
	"1.2.840.113549.1.12.1.4":    "pkcs-12-PBEID-SHA1And2KeyTripleDES-CBC",
	"1.2.840.113549.1.12.1.5":    "pkcs-12-PBEID-SHA1And128BitRC2-CBC",
	"1.2.840.113549.1.12.1.6":    "pkcs-12-PBEID-SHA1And40BitRC2-CBC",
	"1.2.840.113549.1.9.20":      "friendlyName",
	"1.2.840.113549.1.9.21":      "localKeyID",
}

// getOIDName returns the name of oid, or oid itself if it is unknown.
func getOIDName(oid string) string {
	if name, ok := oidNames[oid]; ok {
		return name
	}
	return oid
}

func asn1TagName(tag int) string {
	switch tag {
	case 0:
		return "EOC"
	case 1:
		return "BOOLEAN"
	case 2:
		return "INTEGER"
	case 3:
		return "BIT STRING"
	case 4:
		return "OCTET STRING"
	case 5:
		return "NULL"
	case 6:
		return "OBJECT IDENTIFIER"
	case 7:
		return "Object Descriptor"
	case 8:
		return "EXTERNAL"
	case 9:
		return "REAL"
	case 10:
		return "ENUMERATED"
	case 11:
		return "EMBEDDED PDV"
	case 12:
		return "UTF8String"
	case 13:
		return "RELATIVE-OID"
	case 16:
		return "SEQUENCE"
	case 17:
		return "SET"
	case 18:
		return "NumericString"
	case 19:
		return "PrintableString"
	case 20:
		return "TeletexString"
	case 21:
		return "VideotexString"
	case 22:
		return "IA5String"
	case 23:
		return "UTCTime"
	case 24:
		return "GeneralizedTime"
	case 25:
		return "GraphicString"
	case 26:
		return "VisibleString"
	case 27:
		return "GeneralString"
	case 28:
		return "UniversalString"
	case 30:
		return "BMPString"
	default:
		return "Unknown"
	}
}

// tagName returns the display name of a tag, taking its class into account.
func tagName(class, tag int) string {
	switch class {
	case asn1.ClassUniversal:
		return asn1TagName(tag)
	case asn1.ClassApplication:
		return fmt.Sprintf("[APPLICATION %d]", tag)
	case asn1.ClassContextSpecific:
		return fmt.Sprintf("[%d]", tag)
	default:
		return fmt.Sprintf("[PRIVATE %d]", tag)
	}
}

// parseASN1 appends every TLV in data to result. Errors from nested values
// are returned, so a failed parse can be detected and discarded by the caller.
func parseASN1(data []byte, indent string, result *string) error {
	for len(data) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(data, &value)
		if err != nil {
			return err
		}
		if err := formatValue(value, indent, result); err != nil {
			return err
		}
		data = rest
	}
	return nil
}

// parseNested parses data as embedded DER. It reports false unless all of
// data parses, so a failed attempt leaves no partial output behind.
func parseNested(data []byte, indent string) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	var out string
	if err := parseASN1(data, indent, &out); err != nil {
		return "", false
	}
	return out, true
}

func formatValue(value asn1.RawValue, indent string, result *string) error {
	name := tagName(value.Class, value.Tag)
	if value.IsCompound {
		*result += fmt.Sprintf("%s%s\n", indent, name)
		return parseASN1(value.Bytes, indent+"  ", result)
	}
	if value.Class != asn1.ClassUniversal {
		*result += fmt.Sprintf("%s%s: %x\n", indent, name, value.Bytes)
		return nil
	}

	switch value.Tag {
	case asn1.TagOctetString:
		if nested, ok := parseNested(value.Bytes, indent+"  "); ok {
			*result += fmt.Sprintf("%s%s\n%s", indent, name, nested)
		} else {
			*result += fmt.Sprintf("%s%s: %x\n", indent, name, value.Bytes)
		}
	case asn1.TagBitString:
		var bits asn1.BitString
		if _, err := asn1.Unmarshal(value.FullBytes, &bits); err != nil {
			return fmt.Errorf("decoding BIT STRING: %w", err)
		}
		unused := len(bits.Bytes)*8 - bits.BitLength
		if unused == 0 {
			if nested, ok := parseNested(bits.Bytes, indent+"  "); ok {
				*result += fmt.Sprintf("%s%s (0 unused bits)\n%s", indent, name, nested)
				return nil
			}
		}
		*result += fmt.Sprintf("%s%s (%d unused bits): %x\n", indent, name, unused, bits.Bytes)
	case asn1.TagOID:
		var oid asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(value.FullBytes, &oid)
		if err != nil || len(rest) > 0 {
			fmt.Printf("Error decoding OID")
		}
		*result += fmt.Sprintf("%s%s: %s\n", indent, name, getOIDName(oid.String()))
	case asn1.TagNull:
		*result += fmt.Sprintf("%s%s\n", indent, name)
	case asn1.TagUTCTime, asn1.TagGeneralizedTime:
		var t time.Time
		if _, err := asn1.Unmarshal(value.FullBytes, &t); err != nil {
			*result += fmt.Sprintf("%s%s: %s\n", indent, name, printable(value.Bytes))
		} else {
			*result += fmt.Sprintf("%s%s: %s (%s)\n", indent, name, value.Bytes, t.UTC().Format(time.RFC3339))
		}
	case asn1.TagUTF8String, asn1.TagNumericString, asn1.TagPrintableString, asn1.TagT61String,
		asn1.TagIA5String, 21 /* VideotexString */, 25 /* GraphicString */, 26 /* VisibleString */, asn1.TagGeneralString:
		*result += fmt.Sprintf("%s%s: %s\n", indent, name, printable(value.Bytes))
	case asn1.TagBMPString:
		*result += fmt.Sprintf("%s%s: %s\n", indent, name, decodeUCS(value.Bytes, 2))
	case 28: // UniversalString
		*result += fmt.Sprintf("%s%s: %s\n", indent, name, decodeUCS(value.Bytes, 4))
	default:
		*result += fmt.Sprintf("%s%s: %x\n", indent, name, value.Bytes)
	}
	return nil
}

// printable returns b as text if it is valid, printable UTF-8, and as hex otherwise.
func printable(b []byte) string {
	s := string(b)
	if !utf8.ValidString(s) {
		return fmt.Sprintf("%x", b)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return fmt.Sprintf("%x", b)
		}
	}
	return s
}

// decodeUCS decodes big-endian UCS-2 (BMPString, width 2) or UCS-4
// (UniversalString, width 4) text, falling back to hex if b is malformed.
func decodeUCS(b []byte, width int) string {
	if len(b)%width != 0 {
		return fmt.Sprintf("%x", b)
	}
	var s []byte
	for i := 0; i < len(b); i += width {
		var r rune
		for _, c := range b[i : i+width] {
			r = r<<8 | rune(c)
		}
		if !utf8.ValidRune(r) {
			return fmt.Sprintf("%x", b)
		}
		s = utf8.AppendRune(s, r)
	}
	return printable(s)
}

func parseDER(filePath string, result *string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	err = parseASN1(data, "", result)
	if err != nil {
		fmt.Println("Error parsing ASN.1 data:", err)
		os.Exit(1)
	}
}

func main() {

	var result string
	// Define a string flag with a default value and a usage description
	format := flag.String("inform", "DER", "a name to greet")

	flag.Parse()

	filepath := flag.Args()

	if len(filepath) != 1 {
		fmt.Println("Please provide exactly one file path as an argument.")
		os.Exit(1)
	}

	if *format == "DER" {
		parseDER(filepath[0], &result)
	} else if *format == "PEM" {
		// Process the file in PEM format
		fmt.Printf("Processing file %s in PEM format...\n", filepath[0])
		// Add your PEM processing logic here
	} else {
		fmt.Println("Invalid format. Please use 'DER' or 'PEM'.")
		os.Exit(1)
	}

	fmt.Println("ASN.1 Parsed Output:")
	fmt.Println(result)

}
