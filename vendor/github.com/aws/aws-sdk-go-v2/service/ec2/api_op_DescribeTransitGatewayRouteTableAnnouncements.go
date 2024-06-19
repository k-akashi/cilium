// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Describes one or more transit gateway route table advertisements.
func (c *Client) DescribeTransitGatewayRouteTableAnnouncements(ctx context.Context, params *DescribeTransitGatewayRouteTableAnnouncementsInput, optFns ...func(*Options)) (*DescribeTransitGatewayRouteTableAnnouncementsOutput, error) {
	if params == nil {
		params = &DescribeTransitGatewayRouteTableAnnouncementsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeTransitGatewayRouteTableAnnouncements", params, optFns, c.addOperationDescribeTransitGatewayRouteTableAnnouncementsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeTransitGatewayRouteTableAnnouncementsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeTransitGatewayRouteTableAnnouncementsInput struct {

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The filters associated with the transit gateway policy table.
	Filters []types.Filter

	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	MaxResults *int32

	// The token for the next page of results.
	NextToken *string

	// The IDs of the transit gateway route tables that are being advertised.
	TransitGatewayRouteTableAnnouncementIds []string

	noSmithyDocumentSerde
}

type DescribeTransitGatewayRouteTableAnnouncementsOutput struct {

	// The token for the next page of results.
	NextToken *string

	// Describes the transit gateway route table announcement.
	TransitGatewayRouteTableAnnouncements []types.TransitGatewayRouteTableAnnouncement

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeTransitGatewayRouteTableAnnouncementsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeTransitGatewayRouteTableAnnouncements{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeTransitGatewayRouteTableAnnouncements{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeTransitGatewayRouteTableAnnouncements"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeTransitGatewayRouteTableAnnouncements(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

// DescribeTransitGatewayRouteTableAnnouncementsAPIClient is a client that
// implements the DescribeTransitGatewayRouteTableAnnouncements operation.
type DescribeTransitGatewayRouteTableAnnouncementsAPIClient interface {
	DescribeTransitGatewayRouteTableAnnouncements(context.Context, *DescribeTransitGatewayRouteTableAnnouncementsInput, ...func(*Options)) (*DescribeTransitGatewayRouteTableAnnouncementsOutput, error)
}

var _ DescribeTransitGatewayRouteTableAnnouncementsAPIClient = (*Client)(nil)

// DescribeTransitGatewayRouteTableAnnouncementsPaginatorOptions is the paginator
// options for DescribeTransitGatewayRouteTableAnnouncements
type DescribeTransitGatewayRouteTableAnnouncementsPaginatorOptions struct {
	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeTransitGatewayRouteTableAnnouncementsPaginator is a paginator for
// DescribeTransitGatewayRouteTableAnnouncements
type DescribeTransitGatewayRouteTableAnnouncementsPaginator struct {
	options   DescribeTransitGatewayRouteTableAnnouncementsPaginatorOptions
	client    DescribeTransitGatewayRouteTableAnnouncementsAPIClient
	params    *DescribeTransitGatewayRouteTableAnnouncementsInput
	nextToken *string
	firstPage bool
}

// NewDescribeTransitGatewayRouteTableAnnouncementsPaginator returns a new
// DescribeTransitGatewayRouteTableAnnouncementsPaginator
func NewDescribeTransitGatewayRouteTableAnnouncementsPaginator(client DescribeTransitGatewayRouteTableAnnouncementsAPIClient, params *DescribeTransitGatewayRouteTableAnnouncementsInput, optFns ...func(*DescribeTransitGatewayRouteTableAnnouncementsPaginatorOptions)) *DescribeTransitGatewayRouteTableAnnouncementsPaginator {
	if params == nil {
		params = &DescribeTransitGatewayRouteTableAnnouncementsInput{}
	}

	options := DescribeTransitGatewayRouteTableAnnouncementsPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeTransitGatewayRouteTableAnnouncementsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeTransitGatewayRouteTableAnnouncementsPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeTransitGatewayRouteTableAnnouncements page.
func (p *DescribeTransitGatewayRouteTableAnnouncementsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeTransitGatewayRouteTableAnnouncementsOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.NextToken = p.nextToken

	var limit *int32
	if p.options.Limit > 0 {
		limit = &p.options.Limit
	}
	params.MaxResults = limit

	result, err := p.client.DescribeTransitGatewayRouteTableAnnouncements(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.NextToken

	if p.options.StopOnDuplicateToken &&
		prevToken != nil &&
		p.nextToken != nil &&
		*prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opDescribeTransitGatewayRouteTableAnnouncements(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeTransitGatewayRouteTableAnnouncements",
	}
}
