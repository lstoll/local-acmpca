package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
)

type server struct {
}

func (s *server) CreateCertificateAuthority(ctx context.Context, log *slog.Logger, req *acmpca.CreateCertificateAuthorityInput) (*acmpca.CreateCertificateAuthorityOutput, error) {
	log.Info("create CA", "ca", fmt.Sprintf("%#v", req))
	return &acmpca.CreateCertificateAuthorityOutput{
		CertificateAuthorityArn: aws.String("arn:aws:lol"),
	}, nil
}

func (s *server) IssueCertificate(ctx context.Context, log *slog.Logger, req *acmpca.IssueCertificateInput) (*acmpca.IssueCertificateOutput, error) {
	log.Info("issue Cert", "req", fmt.Sprintf("%#v", req))
	return &acmpca.IssueCertificateOutput{
		CertificateArn: aws.String("arn:aws:lol"),
	}, nil
}

func (s *server) GetCertificate(ctx context.Context, log *slog.Logger, req *acmpca.GetCertificateInput) (*acmpca.GetCertificateOutput, error) {
	log.Info("get cert", "req", fmt.Sprintf("%#v", req))
	return &acmpca.GetCertificateOutput{
		Certificate: aws.String("---BEGIN---"),
	}, nil
}

func (s *server) DeleteCertificateAuthority(ctx context.Context, log *slog.Logger, req *acmpca.DeleteCertificateAuthorityInput) (*acmpca.DeleteCertificateAuthorityOutput, error) {
	log.Info("delete CA", "ca", fmt.Sprintf("%#v", req))
	return &acmpca.DeleteCertificateAuthorityOutput{}, nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("got req: %#v", r)
	log.Printf("got req url: %s", r.URL.String())
	b, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	log.Printf("got body: %s", string(b))
	r.Body = io.NopCloser(bytes.NewReader(b))

	amzTarget := r.Header.Get("X-Amz-Target")
	spAmzTarget := strings.Split(amzTarget, ".")
	if amzTarget == "" || len(spAmzTarget) != 2 || spAmzTarget[0] != "ACMPrivateCA" {
		slog.ErrorContext(r.Context(), "Invalid X-Amz-Target specified", "target", amzTarget)
		http.Error(w, "Invalid X-Amz-Target specified", http.StatusBadRequest)
		return
	}

	switch spAmzTarget[1] {
	case "CreateCertificateAuthority":
		handleAPICall(r.Context(), slog.With("call", "CreateCertificateAuthority"), w, r, s.CreateCertificateAuthority)
	case "IssueCertificate":
		handleAPICall(r.Context(), slog.With("call", "IssueCertificate"), w, r, s.IssueCertificate)
	case "GetCertificate":
		handleAPICall(r.Context(), slog.With("call", "GetCertificate"), w, r, s.GetCertificate)
	case "DeleteCertificateAuthority":
		handleAPICall(r.Context(), slog.With("call", "CreateCertificateAuthority"), w, r, s.DeleteCertificateAuthority)
	default:
		slog.WarnContext(r.Context(), "Unhandled API call", "call", spAmzTarget[1])
		http.Error(w, "Unhandled API call "+spAmzTarget[1], http.StatusNotFound)
		return
	}
}

func handleAPICall[In any, Out any](ctx context.Context, log *slog.Logger, w http.ResponseWriter, r *http.Request, handler func(context.Context, *slog.Logger, *In) (*Out, error)) {
	slog.InfoContext(ctx, "Handling API call")

	req := new(In)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		slog.ErrorContext(r.Context(), "parsing request failed", "err", err)
		http.Error(w, "Parsing request failed", http.StatusBadRequest)
		return
	}

	resp, err := handler(ctx, log, req)
	if err != nil {
		slog.ErrorContext(r.Context(), "handler failed", "err", err)
		http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.ErrorContext(r.Context(), "Error encoding response", "err", err)
		http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	slog.InfoContext(ctx, "API call finished")
}
