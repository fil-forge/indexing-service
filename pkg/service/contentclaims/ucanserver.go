package contentclaims

import (
	"github.com/fil-forge/indexing-service/pkg/types"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/server"
)

func NewUCANServer(id principal.Signer, service types.Publisher, options ...server.HTTPOption) (*server.HTTPServer, error) {
	ucanServer := server.NewHTTP(id, options...)
	ucanService := NewUCANService(service)
	for command, handler := range ucanService {
		ucanServer.Handle(command, handler)
	}
	return ucanServer, nil
}
