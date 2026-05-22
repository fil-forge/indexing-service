package blobindexlookup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/fil-forge/indexing-service/pkg/types"
	"github.com/fil-forge/libforge/blobindex"
	"github.com/fil-forge/libforge/ucan/retrieval"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/ipni/go-libipni/find/model"
)

type simpleLookup struct {
	httpClient *http.Client
}

var _ BlobIndexLookup = (*simpleLookup)(nil)

func NewBlobIndexLookup(httpClient *http.Client) BlobIndexLookup {
	return &simpleLookup{httpClient}
}

// Find fetches the blob index from the given fetchURL
func (s *simpleLookup) Find(ctx context.Context, _ types.EncodedContextID, result model.ProviderResult, request types.RetrievalRequest) (blobindex.ShardedDagIndex, error) {
	var body io.ReadCloser
	// Make a UCAN authorized retrieval request.
	body, err := doAuthorizedRetrieval(ctx, s.httpClient, request)
	if err != nil {
		return nil, fmt.Errorf("executing authorized retrieval: %w", err)
	}
	defer body.Close()
	return blobindex.Extract(body)
}

func doAuthorizedRetrieval(ctx context.Context, httpClient *http.Client, request types.RetrievalRequest) (io.ReadCloser, error) {
	headers := http.Header{}
	if request.Range != nil {
		headers.Set("Range", fmt.Sprintf("bytes=%d-%d", request.Range.Start, request.Range.End))
	}

	c, err := retrieval.NewClient(
		&request.URL,
		retrieval.WithHTTPClient(httpClient),
		retrieval.WithHTTPHeaders(headers),
	)
	if err != nil {
		return nil, err
	}

	prfLinks := make([]cid.Cid, 0, len(request.Auth.Proofs))
	for _, p := range request.Auth.Proofs {
		prfLinks = append(prfLinks, p.Link())
	}

	inv, err := invocation.Invoke(
		request.Auth.Issuer,
		request.Auth.Subject,
		request.Auth.Command,
		request.Auth.Arguments,
		invocation.WithProofs(prfLinks...),
		invocation.WithAudience(request.Auth.Audience),
	)
	if err != nil {
		return nil, err
	}

	res, err := c.Execute(execution.NewRequest(ctx, inv, execution.WithDelegations(request.Auth.Proofs...)))
	if err != nil {
		return nil, fmt.Errorf("executing retrieval invocation: %w", err)
	}

	meta, ok := res.Metadata().(*retrieval.HTTPHeaderResponseContainer)
	if !ok {
		return nil, errors.New("unexpected response metadata type")
	}
	if meta.StatusCode != http.StatusOK && meta.StatusCode != http.StatusPartialContent {
		defer meta.Body.Close()
		body, err := io.ReadAll(meta.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
		return nil, fmt.Errorf("retrieval failed with status code: %d, body: %s", meta.StatusCode, string(body))
	}
	return meta.Body, nil
}
