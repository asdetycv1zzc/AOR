package repository

import "context"

// VerifySubmission validates the durable submission and its Repository Service signature.
func VerifySubmission(ctx context.Context, submission Submission, signer Signer) error {
	if ctx == nil || ctx.Err() != nil || signer == nil || validateStoredSubmission(submission) != nil {
		return ErrInvalidRequest
	}
	payload, err := manifestPayload(submission.Manifest)
	if err != nil || signer.Verify(ctx, payload, submission.Manifest.Signature) != nil {
		return ErrInvalidRequest
	}
	return nil
}
