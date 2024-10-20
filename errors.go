package main

import "fmt"

type apiErrorCode string

const (
	codeInternalFailure apiErrorCode = "InternalFailure"
	codeInvalidArgs     apiErrorCode = "InvalidArgsException"
)

type apiError struct {
	Code      apiErrorCode `json:"code"`
	Message   string       `json:"message"`
	RequestID string       `json:"requestId"`
}

func (a *apiError) Error() string {
	return ""
}

func newAPIErrorf(code apiErrorCode, format string, args ...any) *apiError {
	return &apiError{
		Code:      code,
		Message:   fmt.Sprintf(format, args...),
		RequestID: "00000000-00000000-00000000-00000000",
	}
}
