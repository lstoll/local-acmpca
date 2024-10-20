package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"crawshaw.dev/jsonfile"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

type state struct {
	CertificateAuthorities map[string]certificateAuthority `json:"certificateAuthorities"` // arn -> ca
}

func loadDB(path string) (*jsonfile.JSONFile[state], error) {
	db, err := jsonfile.Load[state](path)
	if errors.Is(err, os.ErrNotExist) {
		db, err = jsonfile.New[state](path)
	}
	if err != nil {
		return nil, fmt.Errorf("load/create db: %w", err)
	}
	return db, nil
}

type certificateAuthority struct {
	Type         types.CertificateAuthorityType `json:"type"`
	PrivPem      string                         `json:"privPEM"`
	CAPem        string                         `json:"caPEM"`
	KeyAlg       types.KeyAlgorithm             `json:"keyAlgorithm"`
	SigningAlg   types.SigningAlgorithm         `json:"signingAlgorithm"`
	Certificates map[string]certificate         `json:"certificates"` // arn -> certificate
}

type certificate struct {
	PEM      string    `json:"pem"`
	IssuedAt time.Time `json:"issuedAt"`
}
