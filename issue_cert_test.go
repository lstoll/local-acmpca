package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

func TestParseValidity(t *testing.T) {
	baseTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name        string
		validity    types.Validity
		startTime   time.Time
		expected    time.Time
		expectError bool
	}{
		// ValidityPeriodTypeEndDate tests
		{
			name: "EndDate - UTCTime format - year >= 50 (19YY)",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeEndDate,
				Value: aws.Int64(750722201704), // 75-07-22 20:17:04 -> 1975-07-22 20:17:04
			},
			startTime:   baseTime,
			expected:    time.Date(1975, 7, 22, 20, 17, 4, 0, time.UTC),
			expectError: false,
		},
		{
			name: "EndDate - UTCTime format - year < 50 (20YY)",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeEndDate,
				Value: aws.Int64(250722201704), // 25-07-22 20:17:04 -> 2025-07-22 20:17:04
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 7, 22, 20, 17, 4, 0, time.UTC),
			expectError: false,
		},
		{
			name: "EndDate - GeneralizedTime format",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeEndDate,
				Value: aws.Int64(20250722201704), // 2025-07-22 20:17:04
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 7, 22, 20, 17, 4, 0, time.UTC),
			expectError: false,
		},
		{
			name: "EndDate - Invalid format (13 digits)",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeEndDate,
				Value: aws.Int64(1234567890123), // Invalid 13-digit format
			},
			startTime:   baseTime,
			expected:    time.Time{},
			expectError: true,
		},

		// ValidityPeriodTypeAbsolute tests
		{
			name: "Absolute - Unix timestamp",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeAbsolute,
				Value: aws.Int64(1705314600), // 2024-01-15 10:30:00 UTC
			},
			startTime:   baseTime,
			expected:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name: "Absolute - Future timestamp",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeAbsolute,
				Value: aws.Int64(1735734600), // 2025-01-01 12:30:00 UTC
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 1, 12, 30, 0, 0, time.UTC),
			expectError: false,
		},

		// ValidityPeriodTypeDays tests
		{
			name: "Days - 1 day",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeDays,
				Value: aws.Int64(1),
			},
			startTime:   baseTime,
			expected:    time.Date(2024, 1, 16, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name: "Days - 365 days",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeDays,
				Value: aws.Int64(365),
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 14, 10, 30, 0, 0, time.UTC), // 2024 is leap year, so 365 days = 2025-01-14
			expectError: false,
		},
		{
			name: "Days - Leap year handling",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeDays,
				Value: aws.Int64(366), // 2024 is a leap year
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), // 366 days from 2024-01-15 = 2025-01-15
			expectError: false,
		},

		// ValidityPeriodTypeMonths tests
		{
			name: "Months - 1 month",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeMonths,
				Value: aws.Int64(1),
			},
			startTime:   baseTime,
			expected:    time.Date(2024, 2, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name: "Months - 12 months",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeMonths,
				Value: aws.Int64(12),
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},

		// ValidityPeriodTypeYears tests
		{
			name: "Years - 1 year",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeYears,
				Value: aws.Int64(1),
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name: "Years - 10 years",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeYears,
				Value: aws.Int64(10),
			},
			startTime:   baseTime,
			expected:    time.Date(2034, 1, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseValidity(tt.startTime, tt.validity)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !result.Equal(tt.expected) {
				t.Errorf("parseValidity() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestProcessEndEntityCSR_APIPassthrough(t *testing.T) {
	caCert := &x509.Certificate{SubjectKeyId: []byte{0xCA, 0xFE}}

	csrPEM, _ := makeTestCSR(t, pkix.Name{CommonName: "from-csr.example.com"}, []string{"csr-only.example.com"})

	// API passthrough: API Subject and SANs should win over CSR.
	overrideURI, _ := url.Parse("spiffe://example.com/workload")
	req := &acmpca.IssueCertificateInput{
		Csr:         csrPEM,
		TemplateArn: aws.String(templateEndEntityCertificateAPIPassthruV1),
		ApiPassthrough: &types.ApiPassthrough{
			Subject: &types.ASN1Subject{
				CommonName:   aws.String("api.example.com"),
				Organization: aws.String("API Org"),
			},
			Extensions: &types.Extensions{
				SubjectAlternativeNames: []types.GeneralName{
					{DnsName: aws.String("api-san.example.com")},
					{IpAddress: aws.String("10.0.0.1")},
					{UniformResourceIdentifier: aws.String(overrideURI.String())},
					{Rfc822Name: aws.String("ops@example.com")},
				},
				CertificatePolicies: []types.PolicyInformation{
					{CertPolicyId: aws.String("1.3.6.1.4.1.99999.1")},
				},
				CustomExtensions: []types.CustomExtension{
					{
						ObjectIdentifier: aws.String("1.3.6.1.4.1.99999.2"),
						Value:            aws.String("BAYBAgME"), // base64
						Critical:         aws.Bool(true),
					},
				},
			},
		},
	}

	cert, _, err := processEndEntityCSR(templateEndEntityCertificateAPIPassthruV1, caCert, req, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("processEndEntityCSR: %v", err)
	}

	if cert.Subject.CommonName != "api.example.com" {
		t.Errorf("Subject.CommonName = %q, want api.example.com", cert.Subject.CommonName)
	}
	if !slices.Equal(cert.DNSNames, []string{"api-san.example.com"}) {
		t.Errorf("DNSNames = %v, want [api-san.example.com]", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IPAddresses = %v, want [10.0.0.1]", cert.IPAddresses)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != overrideURI.String() {
		t.Errorf("URIs = %v, want [%s]", cert.URIs, overrideURI)
	}
	if !slices.Equal(cert.EmailAddresses, []string{"ops@example.com"}) {
		t.Errorf("EmailAddresses = %v, want [ops@example.com]", cert.EmailAddresses)
	}
	if len(cert.PolicyIdentifiers) != 1 || cert.PolicyIdentifiers[0].String() != "1.3.6.1.4.1.99999.1" {
		t.Errorf("PolicyIdentifiers = %v, want [1.3.6.1.4.1.99999.1]", cert.PolicyIdentifiers)
	}
	if len(cert.ExtraExtensions) != 1 || cert.ExtraExtensions[0].Id.String() != "1.3.6.1.4.1.99999.2" || !cert.ExtraExtensions[0].Critical {
		t.Errorf("ExtraExtensions = %+v, want one critical extension with OID 1.3.6.1.4.1.99999.2", cert.ExtraExtensions)
	}

	// Template ExtKeyUsage must always come from the template, not the API.
	want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if !slices.Equal(cert.ExtKeyUsage, want) {
		t.Errorf("ExtKeyUsage = %v, want %v", cert.ExtKeyUsage, want)
	}
}

func TestProcessEndEntityCSR_PassthroughRejectedOnNonPassthroughTemplate(t *testing.T) {
	caCert := &x509.Certificate{SubjectKeyId: []byte{0xCA, 0xFE}}
	csrPEM, _ := makeTestCSR(t, pkix.Name{CommonName: "x"}, nil)

	req := &acmpca.IssueCertificateInput{
		Csr: csrPEM,
		ApiPassthrough: &types.ApiPassthrough{
			Subject: &types.ASN1Subject{CommonName: aws.String("api.example.com")},
		},
	}

	if _, _, err := processEndEntityCSR(templateEndEntityCertificateV1, caCert, req, time.Now().Add(time.Hour)); err == nil {
		t.Error("expected error when ApiPassthrough is supplied with a non-passthrough template")
	}
}

func TestProcessEndEntityCSR_NoPassthrough_FallsBackToCSR(t *testing.T) {
	caCert := &x509.Certificate{SubjectKeyId: []byte{0xCA, 0xFE}}
	csrPEM, _ := makeTestCSR(t, pkix.Name{CommonName: "from-csr.example.com"}, []string{"csr.example.com"})

	req := &acmpca.IssueCertificateInput{
		Csr:         csrPEM,
		TemplateArn: aws.String(templateEndEntityCertificateAPIPassthruV1),
	}

	cert, _, err := processEndEntityCSR(templateEndEntityCertificateAPIPassthruV1, caCert, req, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("processEndEntityCSR: %v", err)
	}
	if cert.Subject.CommonName != "from-csr.example.com" {
		t.Errorf("Subject.CommonName = %q, want from-csr.example.com", cert.Subject.CommonName)
	}
	if !slices.Equal(cert.DNSNames, []string{"csr.example.com"}) {
		t.Errorf("DNSNames = %v, want [csr.example.com]", cert.DNSNames)
	}
}

func makeTestCSR(t *testing.T, subject pkix.Name, dnsNames []string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           dnsNames,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), priv
}

