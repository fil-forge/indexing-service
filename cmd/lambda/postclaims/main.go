package main

import (
	"fmt"
	"time"

	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/fil-forge/indexing-service/cmd/lambda"
	"github.com/fil-forge/indexing-service/pkg/aws"
	"github.com/fil-forge/indexing-service/pkg/server"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/utilresolvers"
	"github.com/fil-forge/ucantone/did/web"
	ucanserver "github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/validator"
)

func main() {
	lambda.Start(makeHandler)
}

func makeHandler(cfg aws.Config) any {
	service, err := aws.Construct(cfg)
	if err != nil {
		panic(err)
	}

	wellKnownResolv, err := aws.NewPrincipalMappingResolver(cfg.PrincipalMapping)
	if err != nil {
		return fmt.Errorf("creating principal mapping resolver: %w", err)
	}

	id := identity.Identity{Issuer: cfg.ID}
	doc, err := id.DIDDocument()
	if err != nil {
		return fmt.Errorf("creating DID document: %w", err)
	}
	wellKnownResolv[cfg.ID.DID()] = doc

	httpResolv, err := web.NewResolver()
	if err != nil {
		return fmt.Errorf("creating HTTP resolver: %w", err)
	}
	cacheResolv := utilresolvers.NewCached(httpResolv, time.Hour*3)

	handler := httpadapter.NewV2(
		server.PostClaimsHandler(
			cfg.Issuer,
			service,
			ucanserver.WithValidationOptions(
				validator.WithDIDResolver(utilresolvers.ByMethod{
					"key": key.Resolver,
					"web": utilresolvers.Chain{wellKnownResolv, cacheResolv},
				}),
			),
		),
	).ProxyWithContext

	return handler
}
