package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
)

func (s *server) DeleteCertificateAuthority(ctx context.Context, log *slog.Logger, req *acmpca.DeleteCertificateAuthorityInput) (*acmpca.DeleteCertificateAuthorityOutput, error) {
	if req.CertificateAuthorityArn == nil {
		return nil, newAPIErrorf(codeInvalidParameter, "arn for cert and authority required")
	}

	log.InfoContext(ctx, "Deleting CA", "ca", *req.CertificateAuthorityArn)

	// we don't do any grace period stuff in here now, it just goes. Also no
	// validation that it existed.
	if err := s.db.Write(func(data *state) error {
		delete(data.CertificateAuthorities, *req.CertificateAuthorityArn)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("deleting CA from state failed: %w", err)
	}

	return &acmpca.DeleteCertificateAuthorityOutput{}, nil
}
