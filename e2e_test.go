package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

func TestE2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	svr := &server{}
	httpsvr := httptest.NewServer(svr)

	awscfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("eu-west-2"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("11111111", "222222222", "")),
	)
	if err != nil {
		t.Fatalf("loading aws config: %v", err)
	}

	// Create a new ACM PCA client
	svc := acmpca.NewFromConfig(awscfg, func(o *acmpca.Options) {
		o.BaseEndpoint = &httpsvr.URL
	})
	// Create a new CA
	caInput := &acmpca.CreateCertificateAuthorityInput{
		CertificateAuthorityConfiguration: &types.CertificateAuthorityConfiguration{
			KeyAlgorithm:     types.KeyAlgorithmEcPrime256v1,
			SigningAlgorithm: types.SigningAlgorithmSha256withecdsa,
			Subject: &types.ASN1Subject{
				CommonName:   aws.String("Test CA"),
				Country:      aws.String("US"),
				Organization: aws.String("Example Org"),
			},
		},
		CertificateAuthorityType: types.CertificateAuthorityTypeRoot,
	}
	caOutput, err := svc.CreateCertificateAuthority(context.TODO(), caInput)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	caArn := caOutput.CertificateAuthorityArn
	t.Logf("Created CA with ARN: %s\n", *caArn)

	csr, err := createCSR()
	if err != nil {
		t.Fatal(err)
	}

	certInput := &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: caArn,
		Csr:                     csr,
		SigningAlgorithm:        types.SigningAlgorithmSha256withecdsa,
		Validity: &types.Validity{
			Type:  types.ValidityPeriodTypeDays,
			Value: aws.Int64(365),
		},
	}
	certOutput, err := svc.IssueCertificate(ctx, certInput)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	certArn := certOutput.CertificateArn
	t.Logf("Issued certificate with ARN: %s\n", *certArn)

	getInput := &acmpca.GetCertificateInput{
		CertificateAuthorityArn: caArn,
		CertificateArn:          certArn,
	}
	getOutput, err := svc.GetCertificate(ctx, getInput)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	t.Logf("Issued certificate: %s\n", *getOutput.Certificate)

	deleteInput := &acmpca.DeleteCertificateAuthorityInput{
		CertificateAuthorityArn: caArn,
	}
	_, err = svc.DeleteCertificateAuthority(context.TODO(), deleteInput)
	if err != nil {
		t.Fatalf("Failed to delete CA: %v", err)
	}
	t.Log("Deleted CA")
}

func createCSR() ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Example Org"},
			Country:      []string{"US"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	return csrPEM, nil
}
