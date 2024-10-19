package main

type apiErrorCode string

const (
	codeInternalFailure apiErrorCode = "InternalFailure"
	err                 apiErrorCode = "err"
)

type apiError struct {
	Code      apiErrorCode `json:"code"`
	Message   string       `json:"message"`
	RequestID string       `json:"requestId"`
}

func (a *apiError) Error() string {
	return ""
}

func newAPIError(code apiErrorCode, message string) *apiError {
	return &apiError{
		Code:      code,
		Message:   message,
		RequestID: "00000000-00000000-00000000-00000000",
	}
}
