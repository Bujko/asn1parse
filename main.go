package main

import (
	"encoding/asn1"
	"flag"
	"fmt"
	"os"
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
	"2.5.29.25":            "baseCRLNumber",
	"2.5.29.40":            "certificateIssuer",
	"2.5.29.55":            "attributeCertificateIssuer",
	"2.5.29.38":            "authorityAttributeIdentifier",
	"2.5.29.39":            "roleSpecCertIdentifier",
	"2.5.29.47":            "attributeDescriptorCertificate",
	"2.5.29.48":            "attributeCertificate",
	"2.5.29.49":            "attributeCertificateRevocationList",
	"2.5.29.50":            "attributeCertificateIssuer",
	"2.5.29.51":            "attributeCertificateHolder",
	"2.5.29.52":            "attributeCertificateAttributes",
	"2.5.29.53":            "attributeCertificateExtensions",
	// PKCS1
	"1.2.840.113549.1.1.1":  "rsaEncryption",
	"1.2.840.113549.1.1.2":  "md2WithRSAEncryption",
	"1.2.840.113549.1.1.3":  "md4WithRSAEncryption",
	"1.2.840.113549.1.1.4":  "md5WithRSAEncryption",
	"1.2.840.113549.1.1.5":  "sha1WithRSAEncryption",
	"1.2.840.113549.1.1.7":  "rsaOAEPEncryptionSET",
	"1.2.840.113549.1.1.8":  "mgf1",
	"1.2.840.113549.1.1.9":  "pss",
	"1.2.840.113549.1.1.10": "sha256WithRSAEncryption",
	"1.2.840.113549.1.1.11": "sha384WithRSAEncryption",
	"1.2.840.113549.1.1.12": "sha512WithRSAEncryption",
	"1.2.840.113549.1.1.13": "sha224WithRSAEncryption",
	// PKCS5
	"1.2.840.113549.1.5.1":  "pkcs5-pbeWithMD2AndDES-CBC",
	"1.2.840.113549.1.5.3":  "pkcs5-pbeWithMD5AndDES-CBC",
	"1.2.840.113549.1.5.4":  "pkcs5-pbeWithMD2AndRC2-CBC",
	"1.2.840.113549.1.5.6":  "pkcs5-pbeWithMD5AndRC2-CBC",
	"1.2.840.113549.1.5.10": "pkcs5-pbeWithSHA1AndDES-CBC",
	"1.2.840.113549.1.5.11": "pkcs5-pbeWithSHA1AndRC2-CBC",
	"1.2.840.113549.1.5.12": "pkcs5-PBKDF2",
	"1.2.840.113549.1.5.13": "pkcs5-pbes2",
	"1.2.840.113549.1.5.14": "pkcs5-pbkdf2WithHMAC-SHA1",
	// PKCS7
	"1.2.840.113549.1.7.1": "pkcs7-data",
	"1.2.840.113549.1.7.2": "pkcs7-signedData",
	"1.2.840.113549.1.7.3": "pkcs7-envelopedData",
	"1.2.840.113549.1.7.4": "pkcs7-signedAndEnvelopedData",
	"1.2.840.113549.1.7.5": "pkcs7-digestedData",
	"1.2.840.113549.1.7.6": "pkcs7-encryptedData",
	// PKCS12
	"1.2.840.113549.1.12.10.1.1": "pkcs-12-keyBag",
	"1.2.840.113549.1.12.10.1.2": "pkcs-12-certBag",
	"1.2.840.113549.1.12.10.1.3": "pkcs-12-crlBag",
	"1.2.840.113549.1.12.10.1.4": "pkcs-12-secretBag",
	"1.2.840.113549.1.12.10.1.5": "pkcs-12-safeContentsBag",
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

func parseASN1(data []byte, indent string, result *string) error {
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(data, &value)
	if err != nil {
		fmt.Println("Error parsing ASN.1 data:", err)
		return err
	}

	if value.IsCompound {
		*result += fmt.Sprintf("%s%s, Class: %d\n", indent, asn1TagName(value.Tag), value.Class)
		parseASN1(value.Bytes, indent+"  ", result)
	} else {
		switch value.Tag {
		case asn1.TagOctetString:
			err = parseASN1(value.Bytes, indent+"  ", result)
			if err != nil {
				//*result += fmt.Sprintf("%sValue: %x\n", indent, value.Bytes)
				*result += fmt.Sprintf("%s%s: %x\n", indent, asn1TagName(value.Tag), value.Bytes)
			}
		case asn1.TagOID:
			var oid asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(value.FullBytes, &oid)
			if err != nil || len(rest) > 0 {
				fmt.Printf("Error decoding OID")
			}
			*result += fmt.Sprintf("%s%s: %s\n", indent, asn1TagName(value.Tag), getOIDName(oid.String()))
		case asn1.TagNull:
			*result += fmt.Sprintf("%s%s\n", indent, asn1TagName(value.Tag))
		case asn1.TagPrintableString:
			*result += fmt.Sprintf("%s%s: %s\n", indent, asn1TagName(value.Tag), string(value.Bytes))
		default:
			*result += fmt.Sprintf("%s%s: %x\n", indent, asn1TagName(value.Tag), value.Bytes)
		}
	}

	if len(rest) > 0 {
		parseASN1(rest, indent, result)
	}

	return nil
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
