package contentclaims

import (
	"github.com/fil-forge/indexing-service/pkg/types"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/server"
)

func NewUCANServer(id principal.Signer, service types.Publisher, options ...server.HTTPOption) (*server.HTTPServer, error) {
	ucanServer := server.NewHTTP(id, options...)
	routes := NewUCANService(service)
	for _, route := range routes {
		ucanServer.Handle(route.Command, route.Handler)
	}
	return ucanServer, nil
}
