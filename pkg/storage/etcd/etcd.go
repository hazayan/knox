// Package etcd provides an etcd-based storage backend for Knox.
// This backend is suitable for distributed deployments requiring coordination.
package etcd

import (
	"github.com/hazayan/knox/pkg/types"
	"context"
	"errors"

	"github.com/hazayan/knox/pkg/storage"
)

func init() {
	storage.RegisterBackend("etcd", func(cfg storage.Config) (storage.Backend, error) {
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, errors.New("etcd backend requires EtcdEndpoints")
		}
		return New(cfg.EtcdEndpoints, cfg.EtcdPrefix)
	})
}

// Backend implements storage.Backend using etcd.
type Backend struct {
	// TODO: Implement etcd backend
}

// New creates a new etcd storage backend.
func New(endpoints []string, prefix string) (*Backend, error) {
	return nil, errors.New("etcd backend not yet implemented")
}

// Placeholder methods to satisfy the interface
func (b *Backend) GetKey(ctx context.Context, keyID string) (*types.Key, error) {
	return nil, errors.New("not implemented")
}

func (b *Backend) PutKey(ctx context.Context, key *types.Key) error {
	return errors.New("not implemented")
}

func (b *Backend) DeleteKey(ctx context.Context, keyID string) error {
	return errors.New("not implemented")
}

func (b *Backend) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	return nil, errors.New("not implemented")
}

func (b *Backend) UpdateKey(ctx context.Context, keyID string, updateFn func(*types.Key) (*types.Key, error)) error {
	return errors.New("not implemented")
}

func (b *Backend) Ping(ctx context.Context) error {
	return errors.New("not implemented")
}

func (b *Backend) Close() error {
	return nil
}
