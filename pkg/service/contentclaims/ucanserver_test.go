package contentclaims

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fil-forge/indexing-service/pkg/internal/testutil"
	"github.com/fil-forge/indexing-service/pkg/types"
	"github.com/fil-forge/libforge/commands"
	assertcaps "github.com/fil-forge/libforge/commands/assert"
	claimcaps "github.com/fil-forge/libforge/commands/claim"
	"github.com/fil-forge/ucantone/client"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	srv, err := NewUCANServer(testutil.Service, &mockIndexer{})
	require.NoError(t, err)

	// A storage provider delivering claims to the service.
	provider := testutil.Alice

	httpSrv := httptest.NewServer(srv)
	t.Cleanup(httpSrv.Close)

	srvURL, err := url.Parse(httpSrv.URL)
	require.NoError(t, err)

	httpClient, err := client.NewHTTP(srvURL)
	require.NoError(t, err)

	// Build a self-signed location commitment to attach to the cache invocation.
	locationCommitment := testutil.Must(assertcaps.Location.Invoke(
		testutil.Alice,
		testutil.Alice.DID(),
		&assertcaps.LocationArguments{
			Space:    testutil.Bob.DID(),
			Content:  testutil.RandomMultihash(t),
			Location: []commands.CborURL{commands.CborURL(*testutil.TestURL)},
		},
	))(t)

	// The claims the service accepts on its own authority are delegated: the
	// provider invokes them over the service, presenting the service's own
	// delegation as the proof. This is the shape piri sends.
	cacheProof := testutil.Must(claimcaps.Cache.Delegate(
		testutil.Service, provider.DID(), testutil.Service.DID(),
	))(t)
	cacheInvocation := testutil.Must(claimcaps.Cache.Invoke(
		provider,
		testutil.Service.DID(),
		&claimcaps.CacheArguments{
			Claim: locationCommitment.Link(),
			Provider: claimcaps.Provider{
				Addresses: [][]byte{testutil.RandomMultiaddr(t).Bytes()},
			},
		},
		invocation.WithProofs(cacheProof.Link()),
	))(t)

	equalsProof := testutil.Must(assertcaps.Equals.Delegate(
		testutil.Service, provider.DID(), testutil.Service.DID(),
	))(t)

	invs := []struct {
		name string
		inv  ucan.Invocation
		opts []execution.RequestOption
	}{
		{
			name: assertcaps.Equals.String(),
			inv: testutil.Must(assertcaps.Equals.Invoke(
				provider,
				testutil.Service.DID(),
				&assertcaps.EqualsArguments{
					Content: testutil.RandomMultihash(t),
					Equals:  testutil.RandomCID(t),
				},
				invocation.WithProofs(equalsProof.Link()),
			))(t),
			opts: []execution.RequestOption{execution.WithDelegations(equalsProof)},
		},
		{
			name: assertcaps.Index.String(),
			inv: testutil.Must(assertcaps.Index.Invoke(
				testutil.Service,
				testutil.Service.DID(),
				&assertcaps.IndexArguments{
					Index: testutil.RandomCID(t),
				},
			))(t),
		},
		{
			name: claimcaps.Cache.String(),
			inv:  cacheInvocation,
			opts: []execution.RequestOption{
				execution.WithInvocations(locationCommitment),
				execution.WithDelegations(cacheProof),
			},
		},
	}

	for _, tc := range invs {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := httpClient.Execute(execution.NewRequest(t.Context(), tc.inv, tc.opts...))
			require.NoError(t, err)
			require.False(t, resp.Receipt().Out().IsErr(), "unexpected failure")
		})
	}
}

// TestServerRejectsUnauthorizedClaims covers the checks the claim routes are
// served behind: a claim has to be subjected to the service and issued by
// someone else, so that the authority to make it came from the service. The
// exception is /assert/index, which the upload service invokes self-signed.
func TestServerRejectsUnauthorizedClaims(t *testing.T) {
	srv, err := NewUCANServer(testutil.Service, &mockIndexer{})
	require.NoError(t, err)

	httpSrv := httptest.NewServer(srv)
	t.Cleanup(httpSrv.Close)

	srvURL, err := url.Parse(httpSrv.URL)
	require.NoError(t, err)

	httpClient, err := client.NewHTTP(srvURL)
	require.NoError(t, err)

	stranger := testutil.RandomIssuer(t)
	// A claim subjected to somewhere other than this service, carrying a chain
	// the validator accepts: the other subject delegates the command to the
	// caller, so what rejects the invocation is the subject check rather than
	// the missing proofs.
	elsewhere := testutil.RandomIssuer(t)
	elsewhereProof := testutil.Must(claimcaps.Cache.Delegate(
		elsewhere, stranger.DID(), elsewhere.DID(),
	))(t)

	tests := []struct {
		name    string
		inv     ucan.Invocation
		proofs  []ucan.Delegation
		wantErr error
	}{
		{
			name: "a self-signed cache claim is rejected",
			inv: testutil.Must(claimcaps.Cache.Invoke(
				stranger,
				stranger.DID(),
				&claimcaps.CacheArguments{
					Claim:    testutil.RandomCID(t),
					Provider: claimcaps.Provider{Addresses: [][]byte{testutil.RandomMultiaddr(t).Bytes()}},
				},
				invocation.WithAudience(testutil.Service.DID()),
			))(t),
			wantErr: middleware.ErrSelfSignedInvocation,
		},
		{
			name: "a self-signed equals claim is rejected",
			inv: testutil.Must(assertcaps.Equals.Invoke(
				stranger,
				stranger.DID(),
				&assertcaps.EqualsArguments{
					Content: testutil.RandomMultihash(t),
					Equals:  testutil.RandomCID(t),
				},
				invocation.WithAudience(testutil.Service.DID()),
			))(t),
			wantErr: middleware.ErrSelfSignedInvocation,
		},
		{
			name: "a cache claim subjected elsewhere is rejected",
			inv: testutil.Must(claimcaps.Cache.Invoke(
				stranger,
				elsewhere.DID(),
				&claimcaps.CacheArguments{
					Claim:    testutil.RandomCID(t),
					Provider: claimcaps.Provider{Addresses: [][]byte{testutil.RandomMultiaddr(t).Bytes()}},
				},
				invocation.WithAudience(testutil.Service.DID()),
				invocation.WithProofs(elsewhereProof.Link()),
			))(t),
			proofs:  []ucan.Delegation{elsewhereProof},
			wantErr: middleware.ErrInvalidSubject,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := execution.NewRequest(t.Context(), tt.inv, execution.WithDelegations(tt.proofs...))
			resp, err := httpClient.Execute(req)
			require.NoError(t, err)
			require.ErrorIs(t, receiptFailure(t, resp.Receipt()), tt.wantErr)
		})
	}
}

// receiptFailure decodes the failure a receipt carries, so it can be matched
// against a named sentinel.
func receiptFailure(t *testing.T, rcpt ucan.Receipt) error {
	t.Helper()
	out := rcpt.Out()
	require.True(t, out.IsErr(), "expected a failure receipt")
	_, errBytes := out.Unpack()
	var model edm.ErrorModel
	require.NoError(t, model.UnmarshalCBOR(bytes.NewReader(errBytes)))
	return model
}

type mockIndexer struct{}

func (m *mockIndexer) Get(ctx context.Context, claim cid.Cid) (ucan.Invocation, error) {
	return nil, nil
}

func (m *mockIndexer) Cache(ctx context.Context, provider peer.AddrInfo, claim ucan.Invocation, meta ucan.Container) error {
	return nil
}

func (m *mockIndexer) Publish(ctx context.Context, claim ucan.Invocation, meta ucan.Container) error {
	return nil
}

func (m *mockIndexer) Query(ctx context.Context, q types.Query) (types.QueryResult, error) {
	return nil, nil
}

var _ types.Service = (*mockIndexer)(nil)
