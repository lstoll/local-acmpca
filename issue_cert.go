package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

const defaultTemplate = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"

var templates map[string]func(caCert *x509.Certificate, csrPEM []byte, notAfter time.Time) (*x509.Certificate, crypto.PublicKey, error) = map[string]func(caCert *x509.Certificate, csrPEM []byte, notAfter time.Time) (*x509.Certificate, crypto.PublicKey, error){
	"arn:aws:acm-pca:::template/EndEntityCertificate/V1": processEndEntityCSR,
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

	certTemplate, csrPub, err := templateFn(caCert, req.Csr, notAfter)
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

func processEndEntityCSR(caCert *x509.Certificate, csrPEM []byte, notAfter time.Time) (*x509.Certificate, crypto.PublicKey, error) {
	csrBlock, _ := pem.Decode(csrPEM)
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

	// Create the new certificate based on the CSR and template
	certTemplate := x509.Certificate{
		SerialNumber: mustGenCertSerial(),
		Subject:      csr.Subject, // Passthrough from CSR

		NotBefore: time.Now().Add(-60 * time.Minute),
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Passthrough subject alternative names from CSR
		DNSNames:    csr.DNSNames,
		IPAddresses: csr.IPAddresses,
		URIs:        csr.URIs,

		// Authority Key Identifier from CA's SKI
		AuthorityKeyId: caCert.SubjectKeyId,

		// CRL Distribution Points from CA configuration
		// CRLDistributionPoints: crlDistPoints,
	}

	// Subject Key Identifier derived from CSR's public key
	certTemplate.SubjectKeyId, err = deriveSubjectKeyIdentifier(csr.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive subject key identifier: %v", err)
	}

	return &certTemplate, csr.PublicKey, nil
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

	switch validity.Type {
	case types.ValidityPeriodTypeEndDate:
		// If the Type is END_DATE, we expect the Value to be a Unix timestamp (seconds since epoch)
		endTime = time.Unix(int64(*validity.Value), 0)

	case types.ValidityPeriodTypeAbsolute:
		// For ABSOLUTE, Value is a time.Duration in seconds from the startTime
		endTime = startTime.Add(time.Duration(*validity.Value) * time.Second)

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
