package main

import "context"

type StateStore interface {
	UpsertNode(ctx context.Context, node *NodeIdentity) error
	GetNode(ctx context.Context, nodeID string) (*NodeIdentity, error)
	ListNodes(ctx context.Context) ([]NodeIdentity, error)
	DeleteNode(ctx context.Context, nodeID string) error
}

type LeaseStore interface {
	UpsertLease(ctx context.Context, lease *NodeLease) error
	GetLease(ctx context.Context, nodeID string) (*NodeLease, error)
	DeleteLease(ctx context.Context, nodeID string) error
}

type RouteStore interface {
	AnnounceRoute(ctx context.Context, route *RouteDescriptor) error
	QueryRoutes(ctx context.Context, sourceNode, destinationNode string, limit int) ([]RouteDescriptor, error)
	ListRoutes(ctx context.Context, limit int) ([]RouteDescriptor, error)
	RevokeRoute(ctx context.Context, routeID string) error
}

type TokenStore interface {
	SaveToken(ctx context.Context, token *SessionToken) error
	GetToken(ctx context.Context, tokenValue string) (*SessionToken, error)
	RevokeToken(ctx context.Context, tokenValue string) error
}

type ICEStore interface {
	UpsertICECandidateSet(ctx context.Context, set *ICECandidateSet) error
	GetICECandidateSet(ctx context.Context, nodeID string) (*ICECandidateSet, error)
}

type EventSubscription interface {
	Unsubscribe() error
}

type EventBus interface {
	Publish(ctx context.Context, subject string, payload []byte) error
	Subscribe(subject string, handler func([]byte)) (EventSubscription, error)
	Close() error
}
