// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package heartbeat

import (
	"context"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/promise"
)

// Cell creates a cell responsible for periodically updating the heartbeat key
// in the kvstore.
var Cell = cell.Module(
	"kvstore-heartbeat-updater",
	"KVStore Heartbeat Updater",

	cell.Invoke(func(lc cell.Lifecycle, backendPromise promise.Promise[kvstore.BackendOperations]) {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup

		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				wg.Add(1)
				go func() {
					defer wg.Done()

					backend, err := backendPromise.Await(ctx)
					if err != nil {
						// There's nothing we can actually do here. We are already shutting down
						// (either user-requested or caused by the backend initialization failure).
						return
					}

					Heartbeat(ctx, backend)
				}()
				return nil
			},

			OnStop: func(ctx cell.HookContext) error {
				cancel()
				wg.Wait()
				return nil
			},
		})
	}),
)
