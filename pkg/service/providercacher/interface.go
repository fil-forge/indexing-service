package providercacher

import (
	"context"

	"github.com/fil-forge/go-libstoracha/blobindex"
	"github.com/ipni/go-libipni/find/model"
)

type ProviderCacher interface {
	CacheProviderForIndexRecords(ctx context.Context, provider model.ProviderResult, index blobindex.ShardedDagIndexView) error
}
