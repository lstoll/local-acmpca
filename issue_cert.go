package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

const defaultTemplate = templateEndEntityCertificateV1

const (
	templateEndEntityCertificateV1            = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
	templateEndEntityClientAuthV1             = "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate/V1"
	templateEndEntityServerAuthV1             = "arn:aws:acm-pca:::template/EndEntityServerAuthCertificate/V1"
	templateEndEntityCertificateAPIPassthruV1 = "arn:aws:acm-pca:::template/EndEntityCertificate_APIPassthrough/V1"
)

type templateIssuerFn func(templateARN string, caCert *x509.Certificate, req *acmpca.IssueCertificateInput, notAfter time.Time) (cert *x509.Certificate, csrPub crypto.PublicKey, err error)

var templates map[string]templateIssuerFn = map[string]templateIssuerFn{
	templateEndEntityCertificateV1:            processEndEntityCSR,
	templateEndEntityClientAuthV1:             processEndEntityCSR,
	templateEndEntityServerAuthV1:             processEndEntityCSR,
	templateEndEntityCertificateAPIPassthruV1: processEndEntityCSR,
}

// https://docs.aws.amazon.com/privateca/latest/APIReference/API_IssueCertificate.html
func (s *server) IssueCertificate(ctx context.Context, log *slog.Logger, req *acmpca.IssueCertificateInput) (*acmpca.IssueCertificateOutput, error) {
	if err := validateIssueCertificateInputinputinput(req); err != nil {
		return nil, err
	}

	templateARN := defaultTemplate
	if req.TemplateArn != nil {
		templateARN = *req.TemplateArn
	}
	templateFn, ok := templates[templateARN]
	if !ok {
		return nil, newAPIErrorf(codeInvalidParameter, "template arn %s not supported", templateARN)
	}

	var (
		dbca *certificateAuthority
		err  error
	)
	s.db.Read(func(data *state) {
		ca, ok := data.CertificateAuthorities[*req.CertificateAuthorityArn]
		if !ok {
			err = newAPIErrorf(codeResourceNotFound, "CA %s not found", *req.CertificateAuthorityArn)
			return
		}
		dbca = ca
	})

	caCert, err := parseCertificateFromPEM([]byte(dbca.CAPem))
	if err != nil {
		return nil, fmt.Errorf("parsing ca %s cert: %w", *req.CertificateAuthorityArn, err)
	}

	caKey, err := parsePrivateKeyFromPEM([]byte(dbca.PrivPem))
	if err != nil {
		return nil, fmt.Errorf("parsing ca %s private key: %w", *req.CertificateAuthorityArn, err)
	}

	notAfter, err := parseValidity(time.Now(), *req.Validity)
	if err != nil {
		return nil, newAPIErrorf(codeInvalidArgs, "validity not parseable")
	}

	certTemplate, csrPub, err := templateFn(templateARN, caCert, req, notAfter)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert from template: %w", err)
	}

	// Go doesn't really give us knobs to control the signing algorithm, so just
	// let it use what it uses. We check to make sure what was passed is
	// generally OK, otherwise it doesn't have a massive bearing on use in
	// development.
	switch req.SigningAlgorithm {
	case types.SigningAlgorithmSha256withrsa, types.SigningAlgorithmSha384withrsa, types.SigningAlgorithmSha512withrsa:
		return nil, newAPIErrorf(codeInvalidParameter, "RSA not currently supported")
	case types.SigningAlgorithmSha256withecdsa, types.SigningAlgorithmSha384withecdsa, types.SigningAlgorithmSha512withecdsa:
	default:
		return nil, newAPIErrorf(codeInvalidParameter, "Unknown signing algorithm %s", req.SigningAlgorithm)
	}

	signedCert, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csrPub, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signedCert,
	})

	// Appears to be the serial number, so use that.
	certARN := fmt.Sprintf("%s/certificate/%s", *req.CertificateAuthorityArn, certTemplate.SerialNumber.Text(16))
	if !isValidCertARN(certARN) {
		panic("generating invalid cert ARNs")
	}

	if err := s.db.Write(func(data *state) error {
		ca := data.CertificateAuthorities[*req.CertificateAuthorityArn]
		if ca.Certificates == nil {
			ca.Certificates = make(map[string]*certificate, 1)
		}
		ca.Certificates[certARN] = &certificate{
			PEM:      string(certPEM),
			IssuedAt: time.Now(),
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("updating state failed: %w", err)
	}

	return &acmpca.IssueCertificateOutput{
		CertificateArn: &certARN,
	}, nil
}

func processEndEntityCSR(templateARN string, caCert *x509.Certificate, req *acmpca.IssueCertificateInput, notAfter time.Time) (*x509.Certificate, crypto.PublicKey, error) {
	csrBlock, _ := pem.Decode(req.Csr)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, nil, fmt.Errorf("failed to decode CSR")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	err = csr.CheckSignature()
	if err != nil {
		return nil, nil, fmt.Errorf("CSR signature invalid: %v", err)
	}

	allowAPIPassthrough := templateARN == templateEndEntityCertificateAPIPassthruV1

	if !allowAPIPassthrough && req.ApiPassthrough != nil {
		return nil, nil, newAPIErrorf(codeInvalidParameter, "ApiPassthrough is only valid with an APIPassthrough template")
	}

	// Subject: per AWS docs, APIPassthrough templates take Subject from the API
	// when provided, falling back to the CSR. Non-passthrough templates always
	// use the CSR subject.
	subject := csr.Subject
	if allowAPIPassthrough && req.ApiPassthrough != nil && req.ApiPassthrough.Subject != nil {
		subject = convertASN1SubjectToPKIXName(req.ApiPassthrough.Subject)
	}

	// Create the new certificate based on the CSR and template
	certTemplate := x509.Certificate{
		SerialNumber: mustGenCertSerial(),
		Subject:      subject,

		NotBefore: time.Now().Add(-60 * time.Minute),
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Passthrough subject alternative names from CSR
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
		EmailAddresses: csr.EmailAddresses,

		// Authority Key Identifier from CA's SKI
		AuthorityKeyId: caCert.SubjectKeyId,

		// CRL Distribution Points from CA configuration
		// CRLDistributionPoints: crlDistPoints,
	}

	switch templateARN {
	case templateEndEntityCertificateV1, templateEndEntityCertificateAPIPassthruV1:
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case templateEndEntityClientAuthV1:
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case templateEndEntityServerAuthV1:
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	default:
		return nil, nil, fmt.Errorf("template arn %s not supported", templateARN)
	}

	if allowAPIPassthrough && req.ApiPassthrough != nil && req.ApiPassthrough.Extensions != nil {
		if err := applyAPIPassthroughExtensions(&certTemplate, req.ApiPassthrough.Extensions); err != nil {
			return nil, nil, err
		}
	}

	// Subject Key Identifier derived from CSR's public key
	certTemplate.SubjectKeyId, err = deriveSubjectKeyIdentifier(csr.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive subject key identifier: %v", err)
	}

	return &certTemplate, csr.PublicKey, nil
}

// applyAPIPassthroughExtensions merges API-supplied extensions onto a template
// that has already been populated with the template's fixed values. Per AWS
// docs the template's own extensions (KeyUsage, ExtKeyUsage, BasicConstraints)
// take priority and must not be overridden, so those are skipped here. SANs
// from the API replace SANs from the CSR. CertificatePolicies and
// CustomExtensions are passed through.
func applyAPIPassthroughExtensions(cert *x509.Certificate, ext *types.Extensions) error {
	if len(ext.SubjectAlternativeNames) > 0 {
		cert.DNSNames = nil
		cert.IPAddresses = nil
		cert.URIs = nil
		cert.EmailAddresses = nil
		for _, gn := range ext.SubjectAlternativeNames {
			if err := applyGeneralName(cert, gn); err != nil {
				return err
			}
		}
	}

	for _, p := range ext.CertificatePolicies {
		if p.CertPolicyId == nil {
			continue
		}
		oid, err := parseOID(*p.CertPolicyId)
		if err != nil {
			return newAPIErrorf(codeInvalidParameter, "invalid CertPolicyId %q: %v", *p.CertPolicyId, err)
		}
		cert.PolicyIdentifiers = append(cert.PolicyIdentifiers, oid)
	}

	for _, ce := range ext.CustomExtensions {
		if ce.ObjectIdentifier == nil || ce.Value == nil {
			return newAPIErrorf(codeInvalidParameter, "CustomExtension requires ObjectIdentifier and Value")
		}
		oid, err := parseOID(*ce.ObjectIdentifier)
		if err != nil {
			return newAPIErrorf(codeInvalidParameter, "invalid CustomExtension OID %q: %v", *ce.ObjectIdentifier, err)
		}
		raw, err := base64.StdEncoding.DecodeString(*ce.Value)
		if err != nil {
			return newAPIErrorf(codeInvalidParameter, "CustomExtension Value must be base64: %v", err)
		}
		critical := false
		if ce.Critical != nil {
			critical = *ce.Critical
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:       oid,
			Critical: critical,
			Value:    raw,
		})
	}

	return nil
}

func applyGeneralName(cert *x509.Certificate, gn types.GeneralName) error {
	switch {
	case gn.DnsName != nil:
		cert.DNSNames = append(cert.DNSNames, *gn.DnsName)
	case gn.IpAddress != nil:
		ip := net.ParseIP(*gn.IpAddress)
		if ip == nil {
			return newAPIErrorf(codeInvalidParameter, "invalid IpAddress %q", *gn.IpAddress)
		}
		cert.IPAddresses = append(cert.IPAddresses, ip)
	case gn.UniformResourceIdentifier != nil:
		u, err := url.Parse(*gn.UniformResourceIdentifier)
		if err != nil {
			return newAPIErrorf(codeInvalidParameter, "invalid URI %q: %v", *gn.UniformResourceIdentifier, err)
		}
		cert.URIs = append(cert.URIs, u)
	case gn.Rfc822Name != nil:
		cert.EmailAddresses = append(cert.EmailAddresses, *gn.Rfc822Name)
	case gn.DirectoryName != nil:
		// Encode as a directoryName GeneralName extra in SAN. Go doesn't expose
		// directoryName SANs directly, so emit a raw extension if needed. For
		// development use, skip silently if no other names are set.
		return newAPIErrorf(codeInvalidParameter, "DirectoryName SAN not supported")
	default:
		return newAPIErrorf(codeInvalidParameter, "unsupported GeneralName variant")
	}
	return nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return nil, fmt.Errorf("component %q not an integer", p)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("oid must have at least two components")
	}
	return oid, nil
}

func deriveSubjectKeyIdentifier(pubKey crypto.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	hash := sha1.Sum(pubKeyBytes)
	return hash[:], nil
}

func parseValidity(startTime time.Time, validity types.Validity) (time.Time, error) {
	var endTime time.Time

	// https://docs.aws.amazon.com/privateca/latest/APIReference/API_Validity.html

	switch validity.Type {
	case types.ValidityPeriodTypeEndDate:
		// The specific date and time when the certificate will expire,
		// expressed using UTCTime (YYMMDDHHMMSS) or GeneralizedTime
		// (YYYYMMDDHHMMSS) format. When UTCTime is used, if the year field (YY)
		// is greater than or equal to 50, the year is interpreted as 19YY. If
		// the year field is less than 50, the year is interpreted as 20YY.
		dateStr := fmt.Sprintf("%d", *validity.Value)

		var year, month, day, hour, minute, second int
		var err error

		switch len(dateStr) {
		case 12: // UTCTime format: YYMMDDHHMMSS
			_, err = fmt.Sscanf(dateStr, "%2d%2d%2d%2d%2d%2d", &year, &month, &day, &hour, &minute, &second)
			if err != nil {
				return time.Time{}, fmt.Errorf("failed to parse UTCTime format: %w", err)
			}
			// Apply the YY year interpretation rule
			if year >= 50 {
				year += 1900
			} else {
				year += 2000
			}
		case 14: // GeneralizedTime format: YYYYMMDDHHMMSS
			_, err = fmt.Sscanf(dateStr, "%4d%2d%2d%2d%2d%2d", &year, &month, &day, &hour, &minute, &second)
			if err != nil {
				return time.Time{}, fmt.Errorf("failed to parse GeneralizedTime format: %w", err)
			}
		default:
			return time.Time{}, fmt.Errorf("invalid date format: expected 12 digits (UTCTime) or 14 digits (GeneralizedTime), got %d", len(dateStr))
		}

		endTime = time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)

	case types.ValidityPeriodTypeAbsolute:
		// The specific date and time when the validity of a certificate will
		// start or expire, expressed in seconds since the Unix Epoch.
		endTime = time.Unix(int64(*validity.Value), 0)

	// The relative time from the moment of issuance until the certificate will
	// expire, expressed in days, months, or years.

	case types.ValidityPeriodTypeDays:
		// For DAYS, Value is the number of days from the start date
		endTime = startTime.AddDate(0, 0, int(*validity.Value))

	case types.ValidityPeriodTypeMonths:
		// For MONTHS, Value is the number of months from the start date
		endTime = startTime.AddDate(0, int(*validity.Value), 0)

	case types.ValidityPeriodTypeYears:
		// For YEARS, Value is the number of years from the start date
		endTime = startTime.AddDate(int(*validity.Value), 0, 0)

	default:
		return time.Time{}, fmt.Errorf("unsupported validity type: %v", validity.Type)
	}

	return endTime, nil
}

func parseCertificateFromPEM(pemData []byte) (*x509.Certificate, error) {
	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Parse the certificate
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return caCert, nil
}

func parsePrivateKeyFromPEM(pemData []byte) (interface{}, error) {
	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}

	pkcs8PrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		switch key := pkcs8PrivateKey.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("unknown private key type in PKCS#8")
		}
	}

	ecPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return ecPrivateKey, nil
	}

	return nil, errors.New("failed to parse private key, unsupported key type or format")
}

// validateIssueCertificateInputvalidates the acmpca.IssueCertificateInput for required fields
func validateIssueCertificateInputinputinput(input *acmpca.IssueCertificateInput) error {
	// Check if CertificateAuthorityArn is set
	if input.CertificateAuthorityArn == nil || *input.CertificateAuthorityArn == "" {
		return newAPIErrorf(codeInvalidParameter, "CertificateAuthorityArn is required and cannot be empty")
	}

	// Check if Csr is set
	if len(input.Csr) == 0 {
		return newAPIErrorf(codeInvalidParameter, "Csr is required and cannot be empty")
	}

	// Check if SigningAlgorithm is set
	if input.SigningAlgorithm == "" {
		return newAPIErrorf(codeInvalidParameter, "SigningAlgorithm is required and cannot be empty")
	}

	// Check if Validity is set
	if input.Validity == nil {
		return newAPIErrorf(codeInvalidParameter, "Validity is required and cannot be nil")
	}

	// Ensure that Validity has both a Value and a Type
	if input.Validity.Value == nil || *input.Validity.Value <= 0 {
		return newAPIErrorf(codeInvalidParameter, "Validity.Value must be set and greater than 0")
	}
	if input.Validity.Type == "" {
		return newAPIErrorf(codeInvalidParameter, "Validity.Type must be set")
	}

	// Optional: Validate Validity.Type against known values (e.g., DAYS, MONTHS, etc.)
	validTypes := map[types.ValidityPeriodType]bool{
		types.ValidityPeriodTypeDays:     true,
		types.ValidityPeriodTypeMonths:   true,
		types.ValidityPeriodTypeYears:    true,
		types.ValidityPeriodTypeAbsolute: true,
		types.ValidityPeriodTypeEndDate:  true,
	}
	if !validTypes[input.Validity.Type] {
		return newAPIErrorf(codeInvalidParameter, "Validity.Type '%v' is invalid", input.Validity.Type)
	}

	// Optional: Validate IdempotencyToken if provided (not required but useful to ensure length)
	if input.IdempotencyToken != nil && len(*input.IdempotencyToken) > 36 {
		return newAPIErrorf(codeInvalidParameter, "IdempotencyToken must be 36 characters or less")
	}

	// Optional: Ensure that TemplateArn is a valid format if provided
	if input.TemplateArn != nil && *input.TemplateArn == "" {
		return newAPIErrorf(codeInvalidParameter, "TemplateArn is provided but is empty")
	}

	// If no errors, return nil
	return nil
}

func isValidCertARN(arn string) bool {
	return regexp.MustCompile(`^arn:[\w+=/,.@-]+:acm-pca:[\w+=/,.@-]*:[0-9]*:[\w+=,.@-]+(/[\w+=,.@-]+)*$`).MatchString(arn)
}
