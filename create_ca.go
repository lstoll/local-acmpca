package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/google/uuid"
)

// https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html
func (s *server) CreateCertificateAuthority(ctx context.Context, log *slog.Logger, req *acmpca.CreateCertificateAuthorityInput) (*acmpca.CreateCertificateAuthorityOutput, error) {
	if req.CertificateAuthorityConfiguration == nil {
		return nil, newAPIErrorf(codeInvalidArgs, "ca config is missing")
	}
	if req.CertificateAuthorityConfiguration.Subject == nil {
		return nil, newAPIErrorf(codeInvalidArgs, "ca config subject is missing")
	}
	if req.CertificateAuthorityType != types.CertificateAuthorityTypeRoot {
		return nil, newAPIErrorf(codeInvalidArgs, "only root CAs supported")
	}

	arn := &arn.ARN{
		Partition: "aws",
		Service:   "acm-pca",
		Region:    s.region,
		AccountID: s.accountID,
		Resource:  "certificate-authority/" + uuid.New().String(),
	}

	var (
		priv    crypto.PrivateKey
		pub     crypto.PublicKey
		privPEM string
	)
	switch req.CertificateAuthorityConfiguration.KeyAlgorithm {
	case types.KeyAlgorithmEcPrime256v1:
		p, pem, err := generateECDSAKey(elliptic.P256())
		if err != nil {
			return nil, fmt.Errorf("key generation failed: %w", err)
		}
		priv = p
		pub = &p.PublicKey
		privPEM = pem
	default:
		return nil, newAPIErrorf(codeInvalidArgs, "unhandled key algorithm %s", string(req.CertificateAuthorityConfiguration.KeyAlgorithm))
	}

	keyUsage := x509.KeyUsageDigitalSignature
	// keyUsage |= x509.KeyUsageKeyEncipherment // for RSA only.
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	// good enough
	var serial *big.Int
	if req.CertificateAuthorityConfiguration.Subject.SerialNumber != nil {
		s, err := strconv.Atoi(*req.CertificateAuthorityConfiguration.Subject.SerialNumber)
		if err != nil {
			return nil, newAPIErrorf(codeInvalidArgs, "serial number not integer")
		}
		serial = big.NewInt(int64(s))
	} else {
		serial = mustGenCertSerial()
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      convertASN1SubjectToPKIXName(req.CertificateAuthorityConfiguration.Subject),
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		IsCA:                  true,
		KeyUsage:              keyUsage | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %w", err)
	}

	var certBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("Failed to pem encode cert: %v", err)
	}

	if err := s.db.Write(func(s *state) error {
		if s.CertificateAuthorities == nil {
			s.CertificateAuthorities = make(map[string]certificateAuthority, 1)
		}
		s.CertificateAuthorities[arn.String()] = certificateAuthority{
			Type:       req.CertificateAuthorityType,
			PrivPem:    privPEM,
			CAPem:      certBuf.String(),
			KeyAlg:     req.CertificateAuthorityConfiguration.KeyAlgorithm,
			SigningAlg: req.CertificateAuthorityConfiguration.SigningAlgorithm,
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("writing data: %w", err)
	}

	return &acmpca.CreateCertificateAuthorityOutput{
		CertificateAuthorityArn: aws.String(arn.String()),
	}, nil
}

func generateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, string, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, "", err
	}
	// Convert to PEM format
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, "", err
	}
	privKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return privKey, string(privKeyPem), nil
}

func convertASN1SubjectToPKIXName(subject *types.ASN1Subject) pkix.Name {
	name := pkix.Name{}

	if subject.CommonName != nil {
		name.CommonName = *subject.CommonName
	}

	if subject.Country != nil {
		name.Country = []string{*subject.Country}
	}

	if subject.Organization != nil {
		name.Organization = []string{*subject.Organization}
	}

	if subject.OrganizationalUnit != nil {
		name.OrganizationalUnit = []string{*subject.OrganizationalUnit}
	}

	if subject.Locality != nil {
		name.Locality = []string{*subject.Locality}
	}

	if subject.State != nil {
		name.Province = []string{*subject.State}
	}

	// if subject.GivenName != nil {
	// 	name.GivenName = []string{*subject.GivenName}
	// }

	// if subject.Surname != nil {
	// 	name.Surname = []string{*subject.Surname}
	// }

	if subject.SerialNumber != nil {
		name.SerialNumber = *subject.SerialNumber
	}

	// if subject.Title != nil {
	// 	name.Title = []string{*subject.Title}
	// }

	// if subject.Pseudonym != nil {
	// 	name.Pseudonym = []string{*subject.Pseudonym}
	// }

	// if subject.Initials != nil {
	// 	name.Initials = []string{*subject.Initials}
	// }

	return name
}

func mustGenCertSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}
	return serialNumber
}
