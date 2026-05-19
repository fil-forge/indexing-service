package lib

import (
	"context"
	"fmt"

	"github.com/fil-forge/libforge/didresolver"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/validator"
)

// NewDIDVerifierResolverAdapter creates a temporary adapter for DID resolvers
// until https://github.com/fil-forge/ucantone/pull/7 lands.
func NewDIDVerifierResolverAdapter(resolve didresolver.DIDVerifierResolverFunc) validator.DIDResolverFunc {
	return func(ctx context.Context, input did.DID) ([]did.DID, error) {
		verifier, err := resolve(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("resolving DID %q: %w", input, err)
		}
		return []did.DID{verifier.DID()}, nil
	}
}
