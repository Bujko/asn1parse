package main

import (
	"encoding/asn1"
	"flag"
	"fmt"
	"os"
)

func getOIDName(oid string) string {
	switch oid {
	// X.509
	case "2.5.4.3":
		return "commonName"
	case "2.5.4.6":
		return "countryName"
	case "2.5.4.7":
		return "localityName"
	case "2.5.4.8":
		return "stateOrProvinceName"
	case "2.5.4.10":
		return "organizationName"
	case "2.5.4.11":
		return "organizationalUnitName"
	case "2.5.4.5":
		return "serialNumber"
	case "2.5.4.9":
		return "streetAddress"
	case "2.5.4.12":
		return "title"
	case "2.5.4.13":
		return "description"
	case "2.5.4.15":
		return "businessCategory"
	case "2.5.4.17":
		return "postalCode"
	case "2.5.4.20":
		return "telephoneNumber"
	case "2.5.4.41":
		return "name"
	case "2.5.4.42":
		return "givenName"
	case "2.5.4.43":
		return "initials"
	case "2.5.4.44":
		return "generationQualifier"
	case "2.5.4.46":
		return "dnQualifier"
	case "2.5.4.65":
		return "pseudonym"
	case "1.2.840.113549.1.9.1":
		return "emailAddress"
	case "2.5.29.14":
		return "subjectKeyIdentifier"
	case "2.5.29.15":
		return "keyUsage"
	case "2.5.29.17":
		return "subjectAltName"
	case "2.5.29.18":
		return "issuerAltName"
	case "2.5.29.19":
		return "basicConstraints"
	case "2.5.29.31":
		return "cRLDistributionPoints"
	case "2.5.29.32":
		return "certificatePolicies"
	case "2.5.29.35":
		return "authorityKeyIdentifier"
	case "2.5.29.37":
		return "extendedKeyUsage"
	case "2.5.29.30":
		return "nameConstraints"
	case "2.5.29.33":
		return "policyMappings"
	case "2.5.29.36":
		return "policyConstraints"
	case "2.5.29.54":
		return "inhibitAnyPolicy"
	case "2.5.29.46":
		return "freshestCRL"
	case "2.5.29.20":
		return "cRLNumber"
	case "2.5.29.21":
		return "reasonCode"
	case "2.5.29.27":
		return "deltaCRLIndicator"
	case "2.5.29.28":
		return "issuingDistributionPoint"
	case "2.5.29.23":
		return "holdInstructionCode"
	case "2.5.29.24":
		return "invalidityDate"
	case "2.5.29.56":
		return "noRevAvail"
	case "2.5.29.9":
		return "subjectDirectoryAttributes"
	case "2.5.29.16":
		return "privateKeyUsagePeriod"
	case "2.5.29.25":
		return "baseCRLNumber"
	case "2.5.29.40":
		return "certificateIssuer"
	case "2.5.29.55":
		return "attributeCertificateIssuer"
	case "2.5.29.38":
		return "authorityAttributeIdentifier"
	case "2.5.29.39":
		return "roleSpecCertIdentifier"
	case "2.5.29.47":
		return "attributeDescriptorCertificate"
	case "2.5.29.48":
		return "attributeCertificate"
	case "2.5.29.49":
		return "attributeCertificateRevocationList"
	case "2.5.29.50":
		return "attributeCertificateIssuer"
	case "2.5.29.51":
		return "attributeCertificateHolder"
	case "2.5.29.52":
		return "attributeCertificateAttributes"
	case "2.5.29.53":
		return "attributeCertificateExtensions"
	// PKCS1
	case "1.2.840.113549.1.1.1":
		return "rsaEncryption"
	case "1.2.840.113549.1.1.2":
		return "md2WithRSAEncryption"
	case "1.2.840.113549.1.1.3":
		return "md4WithRSAEncryption"
	case "1.2.840.113549.1.1.4":
		return "md5WithRSAEncryption"
	case "1.2.840.113549.1.1.5":
		return "sha1WithRSAEncryption"
	case "1.2.840.113549.1.1.7":
		return "rsaOAEPEncryptionSET"
	case "1.2.840.113549.1.1.8":
		return "mgf1"
	case "1.2.840.113549.1.1.9":
		return "pss"
	case "1.2.840.113549.1.1.10":
		return "sha256WithRSAEncryption"
	case "1.2.840.113549.1.1.11":
		return "sha384WithRSAEncryption"
	case "1.2.840.113549.1.1.12":
		return "sha512WithRSAEncryption"
	case "1.2.840.113549.1.1.13":
		return "sha224WithRSAEncryption"
	// PKCS5
	case "1.2.840.113549.1.5.1":
		return "pkcs5-pbeWithMD2AndDES-CBC"
	case "1.2.840.113549.1.5.3":
		return "pkcs5-pbeWithMD5AndDES-CBC"
	case "1.2.840.113549.1.5.4":
		return "pkcs5-pbeWithMD2AndRC2-CBC"
	case "1.2.840.113549.1.5.6":
		return "pkcs5-pbeWithMD5AndRC2-CBC"
	case "1.2.840.113549.1.5.10":
		return "pkcs5-pbeWithSHA1AndDES-CBC"
	case "1.2.840.113549.1.5.11":
		return "pkcs5-pbeWithSHA1AndRC2-CBC"
	case "1.2.840.113549.1.5.12":
		return "pkcs5-PBKDF2"
	case "1.2.840.113549.1.5.13":
		return "pkcs5-pbes2"
	case "1.2.840.113549.1.5.14":
		return "pkcs5-pbkdf2WithHMAC-SHA1"
	// PKCS7
	case "1.2.840.113549.1.7.1":
		return "pkcs7-data"
	case "1.2.840.113549.1.7.2":
		return "pkcs7-signedData"
	case "1.2.840.113549.1.7.3":
		return "pkcs7-envelopedData"
	case "1.2.840.113549.1.7.4":
		return "pkcs7-signedAndEnvelopedData"
	case "1.2.840.113549.1.7.5":
		return "pkcs7-digestedData"
	case "1.2.840.113549.1.7.6":
		return "pkcs7-encryptedData"
	// PKCS12
	case "1.2.840.113549.1.12.10.1.1":
		return "pkcs-12-keyBag"
	case "1.2.840.113549.1.12.10.1.2":
		return "pkcs-12-certBag"
	case "1.2.840.113549.1.12.10.1.3":
		return "pkcs-12-crlBag"
	case "1.2.840.113549.1.12.10.1.4":
		return "pkcs-12-secretBag"
	case "1.2.840.113549.1.12.10.1.5":
		return "pkcs-12-safeContentsBag"
	case "1.2.840.113549.1.12.1.1":
		return "pkcs-12-PBEID-SHA1And128BitRC4"
	case "1.2.840.113549.1.12.1.2":
		return "pkcs-12-PBEID-SHA1And40BitRC4"
	case "1.2.840.113549.1.12.1.3":
		return "pkcs-12-PBEID-SHA1And3KeyTripleDES-CBC"
	case "1.2.840.113549.1.12.1.4":
		return "pkcs-12-PBEID-SHA1And2KeyTripleDES-CBC"
	case "1.2.840.113549.1.12.1.5":
		return "pkcs-12-PBEID-SHA1And128BitRC2-CBC"
	case "1.2.840.113549.1.12.1.6":
		return "pkcs-12-PBEID-SHA1And40BitRC2-CBC"
	case "1.2.840.113549.1.9.20":
		return "friendlyName"
	case "1.2.840.113549.1.9.21":
		return "localKeyID"
	default:
		return oid
	}
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
