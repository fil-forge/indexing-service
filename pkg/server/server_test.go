package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fil-forge/indexing-service/pkg/internal/testutil"
	"github.com/fil-forge/indexing-service/pkg/service/contentclaims"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/ipfs/go-datastore"
	"github.com/stretchr/testify/require"
)

// TODO: TestGetClaimsHandler, TestGetIPNICIDHandler,
// and the query/post-claim handler suites still need to be ported to the
// ucantone invocation flow. The legacy go-ucanto-based versions have been
// dropped during the migration.

func TestGetRootHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svr := httptest.NewServer(GetRootHandler(testutil.Service))
		defer svr.Close()

		res, err := http.Get(svr.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)

		bytes, err := io.ReadAll(res.Body)
		require.NoError(t, err)

		require.True(t, strings.Contains(string(bytes), testutil.Service.DID().String()))
	})

	t.Run("did:web", func(t *testing.T) {
		didweb, err := did.Parse("did:web:example.org")
		require.NoError(t, err)

		s := multikey.NewIssuer(didweb, testutil.Service)

		svr := httptest.NewServer(GetRootHandler(s))
		defer svr.Close()

		res, err := http.Get(svr.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)

		bytes, err := io.ReadAll(res.Body)
		require.NoError(t, err)

		body := string(bytes)
		require.Contains(t, body, testutil.Service.Verifier().String())
		require.Contains(t, body, didweb.String())
	})
}

func TestGetClaimHandler(t *testing.T) {
	store := contentclaims.NewStoreFromDatastore(datastore.NewMapDatastore())
	claim := testutil.RandomIndexClaim(t)
	err := store.Put(context.Background(), claim.Link(), claim)
	require.NoError(t, err)

	svr := httptest.NewServer(GetClaimHandler(store))
	defer svr.Close()

	t.Run("success", func(t *testing.T) {
		res, err := http.Get(fmt.Sprintf("%s/claim/%s", svr.URL, claim.Link()))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)

		bytes, err := io.ReadAll(res.Body)
		require.NoError(t, err)

		require.Equal(t, claim.Bytes(), bytes)
	})

	t.Run("not found", func(t *testing.T) {
		res, err := http.Get(fmt.Sprintf("%s/claim/%s", svr.URL, testutil.RandomCID(t)))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, res.StatusCode)
	})

	t.Run("invalid CID", func(t *testing.T) {
		res, err := http.Get(fmt.Sprintf("%s/claim/invalid", svr.URL))
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

func TestGetDIDDocumentHandler(t *testing.T) {
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	handler := GetDIDDocument(multikey.NewIssuer(did.MustParse("did:web:indexer.example"), signer))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/did.json", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, "max-age=300", rec.Header().Get("Cache-Control"))
	require.NotEmpty(t, rec.Header().Get("Last-Modified"))
	etag := rec.Header().Get("ETag")
	require.NotEmpty(t, etag)
	var doc did.Document
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	require.Equal(t, "did:web:indexer.example", doc.ID.String())

	// A client that already holds the document gets a 304.
	req = httptest.NewRequest(http.MethodGet, "/.well-known/did.json", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	handler(rec, req)
	require.Equal(t, http.StatusNotModified, rec.Code)
	require.Empty(t, rec.Body.Bytes())
}
