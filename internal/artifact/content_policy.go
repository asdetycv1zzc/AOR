package artifact

import (
	"errors"
	"io"

	"github.com/akimisaka/aor/internal/credentials"
)

var ErrCredentialDetected = errors.New("credential-like artifact content rejected")

const credentialScanOverlap = 256

func validateContent(data []byte) error {
	if len(credentials.ScanBytes(data)) != 0 {
		return ErrCredentialDetected
	}
	return nil
}

type credentialScanningWriter struct {
	destination io.Writer
	tail        []byte
	err         error
}

func newCredentialScanningWriter(destination io.Writer) *credentialScanningWriter {
	return &credentialScanningWriter{destination: destination}
}

func (writer *credentialScanningWriter) Write(data []byte) (int, error) {
	if writer.err != nil {
		return 0, writer.err
	}
	window := make([]byte, 0, len(writer.tail)+len(data))
	window = append(window, writer.tail...)
	window = append(window, data...)
	if err := validateContent(window); err != nil {
		writer.err = err
		return 0, err
	}
	written, err := writer.destination.Write(data)
	if err != nil {
		writer.err = err
		return written, err
	}
	if written != len(data) {
		writer.err = io.ErrShortWrite
		return written, writer.err
	}
	start := len(window) - credentialScanOverlap
	if start < 0 {
		start = 0
	}
	writer.tail = append(writer.tail[:0], window[start:]...)
	return written, nil
}

func (writer *credentialScanningWriter) Err() error {
	if writer == nil {
		return ErrInvalidRequest
	}
	return writer.err
}
