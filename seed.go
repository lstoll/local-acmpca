package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"time"

	"crawshaw.dev/jsonfile"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"sigs.k8s.io/yaml"
)

type seedFile struct {
	CAs []*struct {
		ARN          string `json:"arn"`
		CommonName   string `json:"cn"`
		KeyAlgorithm string `json:"keyAlgorithm"`
		CAPem        string `json:"caPEM"`
		CAKeyPem     string `json:"caKeyPEM"`
	} `json:"CAs"`
}

// loadAndSeed reads the seed file, and applies it to the given DB. If an entry
// exists, it will not be updated in the state store. If a CA was generated, the
// seed file will be updated in place with it's information, unless skipUpdate
// is set.
func loadAndSeed(path string, db *jsonfile.JSONFile[state], skipUpdate bool) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("loading %s: %w", path, err)
	}
	var sf seedFile
	if err := yaml.UnmarshalStrict(b, &sf); err != nil {
		return fmt.Errorf("unmarshaling %s: %w", path, err)
	}

	var updated bool

	for _, ca := range sf.CAs {
		if !isValidCAArn(ca.ARN) {
			return fmt.Errorf("%s is not a valid CA ARN", ca.ARN)
		}

		log := slog.With("arn", ca.ARN)

		var exists bool
		db.Read(func(data *state) {
			_, exists = data.CertificateAuthorities[ca.ARN]
		})
		if exists {
			log.Info("CA already exists in state, not seeding")
			continue
		}

		if ca.CAPem == "" && ca.CAKeyPem == "" {
			log.Info("CA has no cert/key, provisioning")
			updated = true
			// TODO - when we support more algs/operations, can probably extract
			// this and share with create CA.

			if ca.CommonName == "" {
				ca.CommonName = "local-acmpca Issuer"
			}

			if ca.KeyAlgorithm != string(types.KeyAlgorithmEcPrime256v1) {
				return fmt.Errorf("only key alg %s is supported", types.KeyAlgorithmEcPrime256v1)
			}

			priv, privPem, err := generateECDSAKey(elliptic.P256())
			if err != nil {
				return fmt.Errorf("key generation failed: %w", err)
			}
			ca.CAKeyPem = privPem

			template := x509.Certificate{
				SerialNumber: mustGenCertSerial(),
				Subject: pkix.Name{
					CommonName: ca.CommonName,
				},
				NotBefore: time.Now().Add(-1 * time.Hour),
				NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),

				IsCA:                  true,
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, // update when RSA
				BasicConstraintsValid: true,
				MaxPathLenZero:        true,
			}

			derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
			if err != nil {
				return fmt.Errorf("Failed to create certificate: %w", err)
			}

			ca.CAPem = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
		}

		// if we are here, the ca element is complete and not in the store already. load it.
		if err := db.Write(func(data *state) error {
			if data.CertificateAuthorities == nil {
				data.CertificateAuthorities = make(map[string]*certificateAuthority, 1)
			}
			data.CertificateAuthorities[ca.ARN] = &certificateAuthority{
				Type:       types.CertificateAuthorityTypeRoot,
				PrivPem:    ca.CAKeyPem,
				CAPem:      ca.CAPem,
				KeyAlg:     types.KeyAlgorithmEcPrime256v1,
				SigningAlg: types.SigningAlgorithmSha256withecdsa, // what go is using
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to write state: %w", err)
		}
	}

	if updated && !skipUpdate {
		slog.Info("Updating seed file")
		b, err := yaml.Marshal(sf)
		if err != nil {
			return fmt.Errorf("marshaling config: %w", err)
		}
		if err := os.WriteFile(path, b, 0o0600); err != nil {
			return fmt.Errorf("writing config to %s: %w", path, err)
		}
	}

	return nil
}

func isValidCAArn(arn string) bool {
	return regexp.MustCompile(`^arn:[\w+=/,.@-]+:acm-pca:[\w+=/,.@-]*:[0-9]*:[\w+=,.@-]+(/[\w+=,.@-]+)*$`).MatchString(arn)
}
