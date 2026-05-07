package redis_test

import (
	"context"
	"io"
	"net/url"
	"testing"

	cassert "github.com/fil-forge/go-libstoracha/capabilities/assert"
	ctypes "github.com/fil-forge/go-libstoracha/capabilities/types"
	"github.com/fil-forge/go-libstoracha/testutil"
	"github.com/fil-forge/go-ucanto/core/delegation"
	"github.com/fil-forge/go-ucanto/ucan"
	"github.com/fil-forge/indexing-service/pkg/redis"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"
)

func TestContentClaimsStore(t *testing.T) {
	mockRedis := NewMockRedis()
	contentClaimsStore := redis.NewContentClaimsStore(mockRedis)
	claim1 := cassert.Location.New(testutil.Service.DID().String(), cassert.LocationCaveats{
		Content:  ctypes.FromHash(testutil.RandomMultihash(t)),
		Location: []url.URL{*testutil.Must(url.Parse("https://storacha.network"))(t)},
	})
	delegation1 := testutil.Must(delegation.Delegate(testutil.Service, testutil.Alice, []ucan.Capability[cassert.LocationCaveats]{claim1}))(t)
	claim2 := cassert.Index.New(testutil.Service.DID().String(), cassert.IndexCaveats{
		Content: testutil.RandomCID(t),
		Index:   testutil.RandomCID(t),
	})
	delegation1Cid := testutil.Must(cid.Prefix{
		Version:  1,
		Codec:    cid.Raw,
		MhType:   mh.SHA2_256,
		MhLength: -1,
	}.Sum(testutil.Must(io.ReadAll(delegation.Archive(delegation1)))(t)))(t)
	delegation2 := testutil.Must(delegation.Delegate(testutil.Service, testutil.Service, []ucan.Capability[cassert.IndexCaveats]{claim2}))(t)
	delegation2Cid := testutil.Must(cid.Prefix{
		Version:  1,
		Codec:    cid.Raw,
		MhType:   mh.SHA2_256,
		MhLength: -1,
	}.Sum(testutil.Must(io.ReadAll(delegation.Archive(delegation2)))(t)))(t)
	ctx := context.Background()
	require.NoError(t, contentClaimsStore.Set(ctx, delegation1Cid, delegation1, false))
	require.NoError(t, contentClaimsStore.Set(ctx, delegation2Cid, delegation2, true))

	returnedDelegation1 := testutil.Must(contentClaimsStore.Get(ctx, delegation1Cid))(t)
	returnedDelegation2 := testutil.Must(contentClaimsStore.Get(ctx, delegation2Cid))(t)
	testutil.RequireEqualDelegation(t, delegation1, returnedDelegation1)
	testutil.RequireEqualDelegation(t, delegation2, returnedDelegation2)
}
