// Package etcd provides an etcd-based storage backend for Knox.
// This backend is suitable for distributed deployments requiring coordination.
package etcd

import (
	"context"
	"errors"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/types"
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
func New(_ []string, _ string) (*Backend, error) {
	return nil, errors.New("etcd backend not yet implemented")
}

// GetKey retrieves a key from etcd storage.
func (b *Backend) GetKey(_ context.Context, _ string) (*types.Key, error) {
	return nil, errors.New("not implemented")
}

// PutKey stores a key in etcd storage.
func (b *Backend) PutKey(_ context.Context, _ *types.Key) error {
	return errors.New("not implemented")
}

// DeleteKey removes a key from etcd storage.
func (b *Backend) DeleteKey(_ context.Context, _ string) error {
	return errors.New("not implemented")
}

// ListKeys lists keys from etcd storage.
func (b *Backend) ListKeys(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}

// UpdateKey updates a key in etcd storage.
func (b *Backend) UpdateKey(_ context.Context, _ string, _ func(*types.Key) (*types.Key, error)) error {
	return errors.New("not implemented")
}

// Ping checks etcd connectivity.
func (b *Backend) Ping(_ context.Context) error {
	return errors.New("not implemented")
}

// Close closes the etcd connection.
func (b *Backend) Close() error {
	return nil
}
