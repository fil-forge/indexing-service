package main

import (
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/fil-forge/indexing-service/cmd/lambda"
	"github.com/fil-forge/indexing-service/pkg/aws"
	"github.com/fil-forge/indexing-service/pkg/server"
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

	didResolver, err := aws.NewDIDResolver(cfg)
	if err != nil {
		return err
	}

	handler := httpadapter.NewV2(
		server.PostClaimsHandler(
			cfg.Issuer,
			service,
			ucanserver.WithValidationOptions(validator.WithDIDResolver(didResolver)),
		),
	).ProxyWithContext

	return handler
}
