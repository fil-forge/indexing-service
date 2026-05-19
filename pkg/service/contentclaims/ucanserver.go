package contentclaims

import (
	"github.com/fil-forge/indexing-service/pkg/types"
	assertcaps "github.com/fil-forge/libforge/capabilities/assert"
	claimcaps "github.com/fil-forge/libforge/capabilities/claim"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
)

func NewUCANServer(id principal.Signer, service types.Publisher, options ...server.HTTPOption) (*server.HTTPServer, error) {
	ucanServer := server.NewHTTP(id, options...)
	ucanService := NewUCANService(service)
	// TODO: this can be removed when https://github.com/fil-forge/ucantone/pull/7 lands
	cmdMap := map[ucan.Command]validator.Capability{
		assertcaps.EqualsCommand: assertcaps.Equals,
		assertcaps.IndexCommand:  assertcaps.Index,
		claimcaps.CacheCommand:   claimcaps.Cache,
	}
	for command, handler := range ucanService {
		ucanServer.Handle(cmdMap[command], handler)
	}
	return ucanServer, nil
}
