package contentclaims

import (
	"github.com/fil-forge/indexing-service/pkg/types"
	assertcaps "github.com/fil-forge/libforge/commands/assert"
	claimcaps "github.com/fil-forge/libforge/commands/claim"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519/verifier"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/ucan"
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

var log = logging.Logger("contentclaims")

// NewUCANService returns the routes that serve the content claims, each behind
// the authorization it needs. A claim is accepted only from an invocation
// subjected to this service and issued by someone else, so the authority to
// make it traces back to a delegation the service issued. A self-signed
// invocation carries no proofs at all, and /claim/cache reads the caching
// provider's identity straight off the issuer (toPeerID, below), so without
// that check anyone could name themselves the provider for another node's
// content.
//
// /assert/index is the exception: the upload service invokes it self-signed
// over itself, and what authorizes it is the retrieval delegation chain in the
// invocation's metadata rather than the invocation's subject.
func NewUCANService(service types.Publisher, serviceDID did.DID) []server.Route {
	routes := middleware.Apply(
		[]server.Route{
			assertcaps.Equals.Route(
				func(
					req *binding.Request[*assertcaps.EqualsArguments],
					res *binding.Response[*assertcaps.EqualsOK],
				) error {
					claim := req.Invocation()
					err := service.Publish(req.Context(), claim, req.Metadata())
					if err != nil {
						log.Errorf("publishing equals claim: %s", err)
						return err
					}
					return res.SetSuccess(&assertcaps.EqualsOK{})
				},
			),
			claimcaps.Cache.Route(
				func(
					req *binding.Request[*claimcaps.CacheArguments],
					res *binding.Response[*claimcaps.CacheOK],
				) error {
					args := req.Task().Arguments()
					peerid, err := toPeerID(req.Invocation().Issuer())
					if err != nil {
						return err
					}

					var addrs []multiaddr.Multiaddr
					for _, a := range args.Provider.Addresses {
						ma, err := multiaddr.NewMultiaddrBytes(a)
						if err != nil {
							return err
						}
						addrs = append(addrs, ma)
					}

					provider := peer.AddrInfo{ID: peerid, Addrs: addrs}

					var claim ucan.Invocation
					for _, inv := range req.Metadata().Invocations() {
						if inv.Link() == args.Claim {
							claim = inv
							break
						}
					}
					if claim == nil {
						return res.SetFailure(ErrMissingClaim)
					}

					err = service.Cache(req.Context(), provider, claim, req.Metadata())
					if err != nil {
						log.Errorf("caching claim: %s", err)
						return err
					}
					return res.SetSuccess(&claimcaps.CacheOK{})
				}),
		},
		middleware.NotSelfSigned(),
		middleware.OnlySubject(serviceDID),
	)

	return append(routes, assertcaps.Index.Route(
		func(
			req *binding.Request[*assertcaps.IndexArguments],
			res *binding.Response[*assertcaps.IndexOK],
		) error {
			claim := req.Invocation()
			err := service.Publish(req.Context(), claim, req.Metadata())
			if err != nil {
				log.Errorf("publishing index claim: %s", err)
				return err
			}
			return res.SetSuccess(&assertcaps.IndexOK{})
		},
	))
}

func toPeerID(principal did.DID) (peer.ID, error) {
	vfr, err := verifier.ParseKeyDID(principal.String())
	if err != nil {
		return "", err
	}
	pub, err := crypto.UnmarshalEd25519PublicKey(vfr.Raw())
	if err != nil {
		return "", err
	}
	return peer.IDFromPublicKey(pub)
}
