// Package main gives examples of how to verify AWS Instance Identity Documents
package main

/*

AWS has a method that allows you to describe an instance along with a
signature for verification.

You can find some information on how this works here:
http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html

One area that isn't well described is how to use the /signature endpoint to
verify the instance identity document so you can find code here.  Please note
that this is subject to change and may not work at all since near as I can tell
AWS has never published the RSA public certificate.

Quick and dirty without a whole lot of error checking so beware of simply cutting
and pasting into code.

*/

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/fullsailor/pkcs7"
)

// AWSRSAIIDCert is the RSA public certificate
const AWSRSAIIDCert = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----`

// AWSPKCS7IIDCert is the PKCS7 public certificate
const AWSPKCS7IIDCert = `-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----`

var (
	RSACert *x509.Certificate
	RSACertPEM, _ = pem.Decode([]byte(AWSRSAIIDCert))
	PKCS7Cert *x509.Certificate
	PKCS7CertPEM, _ = pem.Decode([]byte(AWSPKCS7IIDCert))
)

func init() {
	var err error

	if RSACert, err = x509.ParseCertificate(RSACertPEM.Bytes); err != nil {
		panic(err)
	}

	if PKCS7Cert, err = x509.ParseCertificate(PKCS7CertPEM.Bytes); err != nil {
		panic(err)
	}
}

// FetchContents is a basic http body fetch.
func FetchContents(uri string) ([]byte, error) {
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	} else {
			defer response.Body.Close()
			bod, err := ioutil.ReadAll(response.Body)
			if err != nil {
					return nil, err
			}
			return bod, nil
	}
}

// VerifyRSA shows IID Verification through the RSA signature
func VerifyRSA() {
	// This method requires you to fetch the /document and /signature

	fmt.Println("Fetching Identity Instance Document")
	document, err := FetchContents("http://169.254.169.254/latest/dynamic/instance-identity/document")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(document))

	fmt.Println("Fetching RSA Signature")
	RSASig, err := FetchContents("http://169.254.169.254/latest/dynamic/instance-identity/signature")
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(RSASig))
	DecodedRSASig, err := base64.StdEncoding.DecodeString(string(RSASig))
	if err != nil {
		fmt.Println("Failed to Decode Signature: " + err.Error())
	}

	// Loop over several algorithms to show results
	// Entire list for completion, but only uncommented ones work
	algos := map[string]x509.SignatureAlgorithm{
		//"MD2WithRSA": x509.MD2WithRSA,
        //"MD5WithRSA": x509.MD5WithRSA,
        //"SHA1WithRSA": x509.SHA1WithRSA,
        "SHA256WithRSA": x509.SHA256WithRSA,
        //"SHA384WithRSA": x509.SHA384WithRSA,
        //"SHA512WithRSA": x509.SHA512WithRSA,
        //"DSAWithSHA1": x509.DSAWithSHA1,
        "DSAWithSHA256": x509.DSAWithSHA256,
        //"ECDSAWithSHA1": x509.ECDSAWithSHA1,
        "ECDSAWithSHA256": x509.ECDSAWithSHA256,
        //"ECDSAWithSHA384": x509.ECDSAWithSHA384,
        //"ECDSAWithSHA512": x509.ECDSAWithSHA512,
        //"SHA256WithRSAPSS": x509.SHA256WithRSAPSS,
        //"SHA384WithRSAPSS": x509.SHA384WithRSAPSS,
        //"SHA512WithRSAPSS": x509.SHA512WithRSAPSS,
	}

	for k, v := range algos {
		fmt.Printf("Checking against RSA Certificate %s\n", k)
		err = RSACert.CheckSignature(v, document, DecodedRSASig)
		if err != nil {
			fmt.Println("Unable to verify: " + err.Error())
		} else {
			fmt.Println("Verified OK")
		}
	}
}

// VerifyPKCS7 shows IID Verification through PKCS7 Signature
func VerifyPKCS7() {
	// The /pkcs7 endpoint contains the document and the signature

	fmt.Println("Fetching PKCS7 Signature")
	PKCS7Sig, err := FetchContents("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(PKCS7Sig))

	fmt.Println("Checking against PKCS7 Certificate")
	PKCS7SigNew := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", string(PKCS7Sig))

	PKCS7SigBER, PKCS7SigRest := pem.Decode([]byte(PKCS7SigNew))
	if len(PKCS7SigRest) != 0 {
		panic("Failed to decode the PEM encoded PKCS7 signature")
	}

	PKCS7Data, err := pkcs7.Parse(PKCS7SigBER.Bytes)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(PKCS7Data.Content))

	PKCS7Data.Certificates = []*x509.Certificate{PKCS7Cert}

	err = PKCS7Data.Verify()
	if err != nil {
		fmt.Println("Unable to verify: " + err.Error())
	} else {
		fmt.Println("Verified OK")
	}
}

func main() {

	VerifyRSA()

	VerifyPKCS7()
}