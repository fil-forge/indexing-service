package contentclaims

import (
	"github.com/fil-forge/indexing-service/pkg/types"
	assertcaps "github.com/fil-forge/libforge/commands/assert"
	claimcaps "github.com/fil-forge/libforge/commands/claim"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/ucan"
	logging "github.com/ipfs/go-log/v2"
	"github.com/multiformats/go-multiaddr"
)

var log = logging.Logger("contentclaims")

// NewUCANService returns the routes that serve the content claims, each behind
// the authorization it needs. A claim is accepted only from an invocation
// subjected to this service and issued by someone else, so the authority to
// make it traces back to a delegation the service issued. A self-signed
// invocation carries no proofs at all, so without that check anyone could
// cache a claim.
//
// /claim/cache takes a claim only from the node that issued it. The cached
// provider is the key that signed the claim, and the addresses it is served at
// come from the invocation, so an invoker caching another node's claim would
// put its own addresses under that node's name.
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

					var addrs []multiaddr.Multiaddr
					for _, a := range args.Provider.Addresses {
						ma, err := multiaddr.NewMultiaddrBytes(a)
						if err != nil {
							return err
						}
						addrs = append(addrs, ma)
					}

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
					if claim.Issuer() != req.Invocation().Issuer() {
						return res.SetFailure(ErrClaimIssuerMismatch)
					}

					err := service.Cache(req.Context(), addrs, claim, req.Metadata())
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
