package main

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
)

// https://docs.aws.amazon.com/privateca/latest/APIReference/API_GetCertificateAuthorityCertificate.html
func (s *server) GetCACertificate(ctx context.Context, log *slog.Logger, req *acmpca.GetCertificateAuthorityCertificateInput) (*acmpca.GetCertificateAuthorityCertificateOutput, error) {
	if req.CertificateAuthorityArn == nil {
		return nil, newAPIErrorf(codeInvalidParameter, "arn for cert and authority required")
	}

	log.InfoContext(ctx, "Getting CA certificate", "ca", *req.CertificateAuthorityArn)

	var (
		ca  *certificateAuthority
		err error
	)
	s.db.Read(func(data *state) {
		c, ok := data.CertificateAuthorities[*req.CertificateAuthorityArn]
		if !ok {
			err = newAPIErrorf(codeInvalidARN, "no CA found")
			return
		}
		ca = c
	})
	if err != nil {
		return nil, err
	}

	return &acmpca.GetCertificateAuthorityCertificateOutput{
		Certificate: &ca.CAPem,
	}, nil
}
