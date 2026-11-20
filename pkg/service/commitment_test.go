package service

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/fil-forge/go-ipni-tools/pkg/metadata"
	"github.com/fil-forge/indexing-service/pkg/internal/testutil"
	"github.com/fil-forge/indexing-service/pkg/service/blobindexlookup"
	"github.com/fil-forge/indexing-service/pkg/service/contentclaims"
	"github.com/fil-forge/indexing-service/pkg/service/providerindex"
	"github.com/fil-forge/indexing-service/pkg/types"
	"github.com/fil-forge/libforge/commands"
	"github.com/fil-forge/libforge/commands/assert"
	"github.com/fil-forge/libforge/commands/content"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipni/go-libipni/find/model"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newKey(t *testing.T) multikey.Signer {
	t.Helper()
	return testutil.Must(ed25519.Generate())(t)
}

// webNode is a storage node identified by a did:web, with the resolver that
// knows its DID document.
type webNode struct {
	multikey.Issuer
	resolver did.Resolver
}

func newWebNode(t *testing.T, host string) webNode {
	t.Helper()
	d := testutil.Must(did.Parse("did:web:" + host))(t)
	issuer := multikey.NewIssuer(d, newKey(t))
	doc := testutil.Must(identity.Identity{Issuer: issuer}.DIDDocument())(t)
	return webNode{
		Issuer: issuer,
		resolver: resolver.ByMethod{
			"key": key.Resolver,
			"web": resolver.WellKnown{d: doc},
		},
	}
}

// keyPeerID is the peer ID of the key a signer holds.
func keyPeerID(t *testing.T, s multikey.Signer) peer.ID {
	t.Helper()
	v, ok := s.Verifier().(multikey.Verifier)
	require.True(t, ok)
	pub := testutil.Must(crypto.UnmarshalEd25519PublicKey(v.Raw()))(t)
	return testutil.Must(peer.IDFromPublicKey(pub))(t)
}

func locationCommitment(t *testing.T, issuer ucan.Issuer) ucan.Invocation {
	t.Helper()
	return testutil.Must(assert.Location.Invoke(issuer, issuer.DID(), &assert.LocationArguments{
		Space:    testutil.Bob.DID(),
		Content:  testutil.RandomMultihash(t),
		Location: []commands.CborURL{commands.CborURL(*testutil.TestURL)},
	}))(t)
}

// nodeAddrs are the claim and blob addresses a node at host serves.
func nodeAddrs(t *testing.T, host string) []ma.Multiaddr {
	t.Helper()
	base := "/dns/" + host + "/https/http-path/"
	return []ma.Multiaddr{
		testutil.Must(ma.NewMultiaddr(base + url.PathEscape("claim/{claim}")))(t),
		testutil.Must(ma.NewMultiaddr(base + url.PathEscape("blob/{blob}")))(t),
	}
}

func TestSignerPeerID(t *testing.T) {
	t.Run("a did:key issuer is its own key", func(t *testing.T) {
		signer := newKey(t)
		claim := locationCommitment(t, multikey.KeyIssuer(signer))

		got, err := signerPeerID(t.Context(), key.Resolver, claim)
		require.NoError(t, err)
		require.Equal(t, keyPeerID(t, signer), got)
	})

	t.Run("a did:web issuer is the key in its document", func(t *testing.T) {
		node := newWebNode(t, "node.example")
		claim := locationCommitment(t, node)

		got, err := signerPeerID(t.Context(), node.resolver, claim)
		require.NoError(t, err)
		require.Equal(t, keyPeerID(t, node.Issuer), got)
	})

	t.Run("a claim signed by an expired key keeps that key's peer ID", func(t *testing.T) {
		d := testutil.Must(did.Parse("did:web:node.example"))(t)
		oldKey, newKey := newKey(t), newKey(t)
		doc := testutil.Must(identity.Identity{Issuer: multikey.NewIssuer(d, newKey)}.DIDDocument())(t)

		expired := did.DateTimeStamp(time.Now().Add(-time.Hour))
		oldVM := multikey.DeriveVerificationMethod(doc.Fragment("key-1"), oldKey.Verifier().(multikey.Verifier))
		oldVM.Controller = doc.ID
		oldVM.Expires = &expired
		require.NoError(t, doc.VerificationMethods.Add(oldVM))
		require.NoError(t, doc.CapabilityInvocation.Add(oldVM))

		claim := locationCommitment(t, multikey.NewIssuer(d, oldKey))

		got, err := signerPeerID(t.Context(), resolver.WellKnown{d: doc}, claim)
		require.NoError(t, err)
		require.Equal(t, keyPeerID(t, oldKey), got)
	})

	t.Run("a claim no key in the document signed has no provider", func(t *testing.T) {
		node := newWebNode(t, "node.example")
		impostor := multikey.NewIssuer(node.DID(), newKey(t))
		claim := locationCommitment(t, impostor)

		_, err := signerPeerID(t.Context(), node.resolver, claim)
		require.ErrorContains(t, err, "signed the claim")
	})
}

func TestCheckClaimOrigin(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		url     string
		wantErr bool
	}{
		{name: "a did:key names no host", issuer: testutil.Alice.DID().String(), url: "https://anywhere.example/claim/x"},
		{name: "the host the did:web names", issuer: "did:web:node.example", url: "https://node.example/claim/x"},
		{name: "the host is compared without case", issuer: "did:web:Node.Example", url: "https://node.example/claim/x"},
		{name: "the default https port", issuer: "did:web:node.example", url: "https://node.example:443/claim/x"},
		{name: "a port in the did:web", issuer: "did:web:piri-0%3A3000", url: "http://piri-0:3000/claim/x"},
		{name: "a did:web with a path", issuer: "did:web:node.example:nodes:one", url: "https://node.example/claim/x"},
		{name: "another host", issuer: "did:web:node.example", url: "https://other.example/claim/x", wantErr: true},
		{name: "another port", issuer: "did:web:piri-0%3A3000", url: "http://piri-0:4000/claim/x", wantErr: true},
		{name: "a port the did:web does not name", issuer: "did:web:node.example", url: "https://node.example:8443/claim/x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := testutil.Must(did.Parse(tt.issuer))(t)
			claimURL := testutil.Must(url.Parse(tt.url))(t)
			err := checkClaimOrigin(issuer, claimURL)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrClaimOrigin)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCacheLocationCommitment(t *testing.T) {
	t.Run("the provider is the key that signed the commitment", func(t *testing.T) {
		node := newWebNode(t, "node.example")
		claim := locationCommitment(t, node)
		addrs := nodeAddrs(t, "node.example")

		claims := contentclaims.NewMockContentClaimsService(t)
		claims.EXPECT().Cache(mock.Anything, claim).Return(nil)
		provIndex := providerindex.NewMockProviderIndex(t)
		provIndex.EXPECT().
			Cache(mock.Anything, peer.AddrInfo{ID: keyPeerID(t, node.Issuer), Addrs: addrs}, mock.Anything, mock.Anything, mock.Anything).
			Return(nil)

		err := Cache(t.Context(), node.resolver, nil, claims, provIndex, addrs, claim, container.New())
		require.NoError(t, err)
	})

	t.Run("a commitment served from another host is refused", func(t *testing.T) {
		node := newWebNode(t, "node.example")
		claim := locationCommitment(t, node)

		claims := contentclaims.NewMockContentClaimsService(t)
		provIndex := providerindex.NewMockProviderIndex(t)

		err := Cache(t.Context(), node.resolver, nil, claims, provIndex, nodeAddrs(t, "other.example"), claim, container.New())
		require.ErrorIs(t, err, ErrClaimOrigin)
	})

	t.Run("a commitment the issuer's keys did not sign is refused", func(t *testing.T) {
		node := newWebNode(t, "node.example")
		impostor := multikey.NewIssuer(node.DID(), newKey(t))
		claim := locationCommitment(t, impostor)

		claims := contentclaims.NewMockContentClaimsService(t)
		provIndex := providerindex.NewMockProviderIndex(t)

		err := Cache(t.Context(), node.resolver, nil, claims, provIndex, nodeAddrs(t, "node.example"), claim, container.New())
		require.Error(t, err)
	})
}

// indexFetch is what fetchBlobIndex needs to retrieve the index blob a
// did:web node holds: the node's commitment, the IPNI result that points at
// it, and an /assert/index invocation authorizing the retrieval.
type indexFetch struct {
	node       webNode
	commitment ucan.Invocation
	result     model.ProviderResult
	cause      ucan.Invocation
	causeMeta  ucan.Container
}

func newIndexFetch(t *testing.T, nodeHost, servedFrom string) indexFetch {
	t.Helper()
	node := newWebNode(t, nodeHost)
	commitment := locationCommitment(t, node)

	shard := testutil.RandomCID(t)
	length := uint64(64)
	md := testutil.Must((&metadata.LocationCommitmentMetadata{
		Shard: &shard,
		Range: &metadata.Range{Offset: 0, Length: &length},
		Claim: commitment.Link(),
	}).MarshalBinary())(t)

	// The space lets this service retrieve the index, and the upload service
	// passes that on in the assertion.
	space := testutil.RandomIssuer(t)
	retrieve := testutil.Must(content.Retrieve.Delegate(space, testutil.Service.DID(), space.DID()))(t)
	cause := testutil.Must(assert.Index.Invoke(
		testutil.Alice,
		testutil.Alice.DID(),
		&assert.IndexArguments{Index: shard},
		invocation.WithMetadata(datamodel.Map{"retrievalAuth": []any{retrieve.Link()}}),
	))(t)

	return indexFetch{
		node:       node,
		commitment: commitment,
		result: model.ProviderResult{
			ContextID: []byte("context"),
			Metadata:  md,
			Provider:  &peer.AddrInfo{ID: keyPeerID(t, node.Issuer), Addrs: nodeAddrs(t, servedFrom)},
		},
		cause:     cause,
		causeMeta: container.New(container.WithDelegations(retrieve)),
	}
}

func TestFetchBlobIndex(t *testing.T) {
	t.Run("the retrieval is addressed to the commitment's issuer", func(t *testing.T) {
		f := newIndexFetch(t, "node.example", "node.example")
		_, idx := testutil.RandomShardedDagIndex(t, 1)

		claims := contentclaims.NewMockContentClaimsService(t)
		claims.EXPECT().Find(mock.Anything, f.commitment.Link(), mock.Anything).Return(f.commitment, nil)

		var req types.RetrievalRequest
		lookup := blobindexlookup.NewMockBlobIndexLookup(t)
		lookup.EXPECT().
			Find(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Run(func(_ context.Context, _ types.EncodedContextID, _ model.ProviderResult, r types.RetrievalRequest) {
				req = r
			}).
			Return(idx, nil)

		got, err := fetchBlobIndex(t.Context(), testutil.Service, f.node.resolver, lookup, claims, testutil.RandomCID(t), f.result, f.cause, f.causeMeta)
		require.NoError(t, err)
		require.Equal(t, idx, got)
		require.Equal(t, f.node.DID(), req.Auth.Audience)
	})

	t.Run("nothing is retrieved for a commitment served from another host", func(t *testing.T) {
		f := newIndexFetch(t, "node.example", "other.example")

		claims := contentclaims.NewMockContentClaimsService(t)
		claims.EXPECT().Find(mock.Anything, f.commitment.Link(), mock.Anything).Return(f.commitment, nil)
		lookup := blobindexlookup.NewMockBlobIndexLookup(t)

		_, err := fetchBlobIndex(t.Context(), testutil.Service, f.node.resolver, lookup, claims, testutil.RandomCID(t), f.result, f.cause, f.causeMeta)
		require.ErrorIs(t, err, ErrClaimOrigin)
	})

	t.Run("nothing is retrieved for a commitment the node's keys did not sign", func(t *testing.T) {
		f := newIndexFetch(t, "node.example", "node.example")
		forged := locationCommitment(t, multikey.NewIssuer(f.node.DID(), newKey(t)))

		claims := contentclaims.NewMockContentClaimsService(t)
		claims.EXPECT().Find(mock.Anything, f.commitment.Link(), mock.Anything).Return(forged, nil)
		lookup := blobindexlookup.NewMockBlobIndexLookup(t)

		_, err := fetchBlobIndex(t.Context(), testutil.Service, f.node.resolver, lookup, claims, testutil.RandomCID(t), f.result, f.cause, f.causeMeta)
		require.ErrorContains(t, err, "verifying claim")
	})
}
