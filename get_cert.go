package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
)

func (s *server) GetCertificate(ctx context.Context, log *slog.Logger, req *acmpca.GetCertificateInput) (*acmpca.GetCertificateOutput, error) {
	if req.CertificateArn == nil || req.CertificateAuthorityArn == nil {
		return nil, newAPIErrorf(codeInvalidParameter, "arn for cert and authority required")
	}

	log.InfoContext(ctx, "Getting certificate", "arn", *req.CertificateArn, "ca", *req.CertificateAuthorityArn)

	var (
		ca   *certificateAuthority
		cert *certificate
		err  error
	)
	s.db.Read(func(data *state) {
		c, ok := data.CertificateAuthorities[*req.CertificateAuthorityArn]
		if !ok {
			err = newAPIErrorf(codeInvalidARN, "no CA found")
			return
		}
		cr, ok := c.Certificates[*req.CertificateArn]
		if !ok {
			err = newAPIErrorf(codeInvalidARN, "no certificate found")
			return
		}
		ca = c
		cert = cr
	})
	if err != nil {
		return nil, err
	}
	if time.Now().Before(cert.IssuedAt.Add(s.certIssueDelay)) {
		// within the "provisioning" period. This appears to be the right error
		return nil, newAPIErrorf(codeRequestInProgress, "certificate request in progress")
	}

	return &acmpca.GetCertificateOutput{
		Certificate:      &cert.PEM,
		CertificateChain: &ca.CAPem, // we don't do chains right now
	}, nil
}
