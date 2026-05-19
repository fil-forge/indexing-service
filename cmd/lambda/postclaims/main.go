package main

import (
	"fmt"
	"time"

	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/fil-forge/indexing-service/cmd/lambda"
	"github.com/fil-forge/indexing-service/pkg/aws"
	"github.com/fil-forge/indexing-service/pkg/lib"
	"github.com/fil-forge/indexing-service/pkg/server"
	"github.com/fil-forge/libforge/didresolver"
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

	mapResolv, err := didresolver.NewMapResolver(cfg.PrincipalMapping)
	if err != nil {
		panic(fmt.Errorf("creating map resolver: %w", err))
	}
	httpResolv, err := didresolver.NewHTTPResolver()
	if err != nil {
		panic(fmt.Errorf("creating HTTP resolver: %w", err))
	}
	cacheResolv, err := didresolver.NewCachedResolver(httpResolv.Resolve, time.Hour*3)
	if err != nil {
		panic(fmt.Errorf("creating cached HTTP resolver: %w", err))
	}
	tierResolv := didresolver.NewTieredResolver(mapResolv.Resolve, cacheResolv.Resolve)

	handler := httpadapter.NewV2(
		server.PostClaimsHandler(
			cfg.Signer,
			service,
			ucanserver.WithValidationOptions(
				validator.WithDIDResolver(
					lib.NewDIDVerifierResolverAdapter(tierResolv.Resolve),
				),
			),
		),
	).ProxyWithContext

	return handler
}
