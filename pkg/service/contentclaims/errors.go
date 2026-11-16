package contentclaims

import "github.com/fil-forge/ucantone/errors"

var ErrMissingClaim = errors.New("MissingClaim", "Claim data was not found in the invocation payload.")

// ErrClaimIssuerMismatch is returned when a claim is sent for caching by
// anyone but the node that issued it.
var ErrClaimIssuerMismatch = errors.New("ClaimIssuerMismatch", "A claim can be cached only by its issuer.")
