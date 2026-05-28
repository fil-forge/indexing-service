package main

import (
	"context"
	"fmt"
	"time"

	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/fil-forge/indexing-service/cmd/lambda"
	"github.com/fil-forge/indexing-service/pkg/aws"
	"github.com/fil-forge/indexing-service/pkg/server"
	"github.com/fil-forge/libforge/didresolver"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal/verifier"
	ucanserver "github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
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
	selfResolv := didresolver.NewSelfResolver(cfg.ID)
	tierResolv := didresolver.NewTieredResolver(selfResolv.Resolve, mapResolv.Resolve, cacheResolv.Resolve)

	handler := httpadapter.NewV2(
		server.PostClaimsHandler(
			cfg.Signer,
			service,
			ucanserver.WithValidationOptions(
				validator.WithDIDVerifierResolvers(map[string]validator.DIDVerifierResolverFunc{
					"key": func(ctx context.Context, did did.DID) (ucan.Verifier, error) {
						return verifier.FromDIDKey(did)
					},
					"web": tierResolv.Resolve,
				}),
			),
		),
	).ProxyWithContext

	return handler
}
