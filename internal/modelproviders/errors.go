package modelproviders

import "errors"

var (
	ErrInvalidSettings   = errors.New("invalid model provider settings")
	ErrProviderNotFound  = errors.New("model provider is not configured")
	ErrAPIKeyUnavailable = errors.New("model provider API key is unavailable")
	ErrStoreUnavailable  = errors.New("model provider settings store unavailable")
)
