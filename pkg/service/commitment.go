package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/web"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/token"
	"github.com/fil-forge/ucantone/validator"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multicodec"
)

// ErrClaimOrigin is returned when a location commitment issued by a did:web is
// served from a host other than the one the DID names.
var ErrClaimOrigin = errors.New("claim is not served from its issuer's origin")

// signerPeerID returns the libp2p peer ID of the key that signed inv. A
// storage node advertises its commitments to IPNI under the peer ID of the key
// it signs with, so this is the provider a cached commitment belongs to.
//
// The issuer's DID does not say which key signed: a did:web document lists the
// node's current key and may list earlier ones. Every key the document offers
// is tried, whatever its expiry, since a commitment keeps the provider it was
// advertised under after its key is retired.
func signerPeerID(ctx context.Context, resolver did.Resolver, inv ucan.Invocation) (peer.ID, error) {
	doc, err := resolver.Resolve(ctx, inv.Issuer())
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", inv.Issuer(), err)
	}

	var vms []did.VerificationMethod
	if doc.CapabilityInvocation != nil {
		vms = doc.CapabilityInvocation.All()
	} else if doc.VerificationMethods != nil {
		vms = doc.VerificationMethods.All()
	}

	factories := validator.DefaultFactories()
	for _, vm := range vms {
		f, ok := factories[vm.Type]
		if !ok {
			continue
		}
		v, err := f(ctx, vm.Material)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			continue
		}
		if !token.VerifySignature(inv, v) {
			continue
		}
		mk, ok := v.(multikey.Verifier)
		if !ok || mk.Code() != multicodec.Ed25519Pub {
			return "", fmt.Errorf("signing key of %s is not an Ed25519 key", inv.Issuer())
		}
		pub, err := crypto.UnmarshalEd25519PublicKey(mk.Raw())
		if err != nil {
			return "", fmt.Errorf("decoding signing key of %s: %w", inv.Issuer(), err)
		}
		return peer.IDFromPublicKey(pub)
	}
	return "", fmt.Errorf("no key in the DID document of %s signed the claim", inv.Issuer())
}

// checkClaimOrigin requires a claim issued by a did:web to be served from the
// host the DID names. That host is where the issuer's DID document comes from,
// so a claim served there is vouched for by whoever controls the identity, and
// a claim served elsewhere is not. Other DID methods name no host and pass.
//
// A port left out on either side is the default for the claim URL's scheme, so
// did:web:node.example and did:web:node.example%3A443 both match a claim
// served from https://node.example.
func checkClaimOrigin(issuer did.DID, claimURL *url.URL) error {
	if issuer.Method() != web.Method {
		return nil
	}
	named, err := web.Location(issuer)
	if err != nil {
		return fmt.Errorf("%w: %s does not name a host: %v", ErrClaimOrigin, issuer, err)
	}
	host, port := named.Hostname(), named.Port()
	if port == "" {
		port = defaultPort(claimURL.Scheme)
	}

	servedPort := claimURL.Port()
	if servedPort == "" {
		servedPort = defaultPort(claimURL.Scheme)
	}
	if !strings.EqualFold(host, claimURL.Hostname()) || port != servedPort {
		return fmt.Errorf("%w: %s serves a claim issued by %s", ErrClaimOrigin, claimURL.Host, issuer)
	}
	return nil
}

// defaultPort is the port a URL of the given scheme uses when it names none.
func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}
