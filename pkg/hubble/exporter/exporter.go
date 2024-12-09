// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"

	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var _ FlowLogExporter = (*exporter)(nil)

// OnExportEvent is a hook that can be registered on an exporter and is invoked for each event.
//
// Returning false will stop the export pipeline for the current event, meaning the default export
// logic as well as the following hooks will not run.
type OnExportEvent interface {
	OnExportEvent(ctx context.Context, ev *v1.Event, encoder Encoder) (stop bool, err error)
}

// OnExportEventFunc implements OnExportEvent for a single function.
type OnExportEventFunc func(ctx context.Context, ev *v1.Event, encoder Encoder) (stop bool, err error)

// OnExportEventFunc implements OnExportEvent.
func (f OnExportEventFunc) OnExportEvent(ctx context.Context, ev *v1.Event, encoder Encoder) (bool, error) {
	return f(ctx, ev, encoder)
}

// exporter is an implementation of OnDecodedEvent interface that writes Hubble events to a file.
type exporter struct {
	logger  logrus.FieldLogger
	encoder Encoder
	writer  io.WriteCloser
	flow    *flowpb.Flow

<<<<<<< HEAD
	evch []chan *v1.Event
	opts exporteroption.Options
=======
	opts Options
>>>>>>> upstream/main
}

// NewExporter initializes an
// NOTE: Stopped instances cannot be restarted and should be re-created.
func NewExporter(logger logrus.FieldLogger, options ...Option) (*exporter, error) {
	opts := DefaultOptions // start with defaults
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	logger.WithField("options", opts).Info("Configuring Hubble event exporter")
<<<<<<< HEAD
	var writer io.WriteCloser
	// If hubble-export-file-path is set to "stdout", use os.Stdout as the writer.
	if opts.Path == "stdout" {
		writer = os.Stdout
	} else {
		writer = &lumberjack.Logger{
			Filename:   opts.Path,
			MaxSize:    opts.MaxSizeMB,
			MaxBackups: opts.MaxBackups,
			Compress:   opts.Compress,
		}
	}
	exporter, err := newExporter(ctx, logger, writer, opts)
	for i := 0; i < 10; i++ {
		go exporter.DecodeEvent(exporter.evch[i])
	}
	return exporter, err
	//return newExporter(ctx, logger, writer, opts)
=======
	return newExporter(logger, opts)
>>>>>>> upstream/main
}

// newExporter let's you supply your own WriteCloser for tests.
func newExporter(logger logrus.FieldLogger, opts Options) (*exporter, error) {
	writer, err := opts.NewWriterFunc()
	if err != nil {
		return nil, fmt.Errorf("failed to create writer: %w", err)
	}
	encoder, err := opts.NewEncoderFunc(writer)
	if err != nil {
		return nil, fmt.Errorf("failed to create encoder: %w", err)
	}
	var flow *flowpb.Flow
	if opts.FieldMask.Active() {
		flow = new(flowpb.Flow)
		opts.FieldMask.Alloc(flow.ProtoReflect())
	}

	ch := make([]chan *v1.Event, 10)
	for i := 0; i < 10; i++ {
		ch[i] = make(chan *v1.Event, 10000)
	}
	return &exporter{
		logger:  logger,
		encoder: encoder,
		writer:  writer,
		flow:    flow,
		opts:    opts,
		evch:    ch,
	}, nil
}

// Export implements the FlowLogExporter interface.
//
// It takes care of applying filters on the received event, and if allowed, proceeds to invoke the
// registered OnExportEvent hooks. If none of the hooks return true (abort signal) the event is then
// wrapped in observerpb.ExportEvent before being encoded and written to its underlying writer.
func (e *exporter) Export(ctx context.Context, ev *v1.Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !filters.Apply(e.opts.AllowFilters(), e.opts.DenyFilters(), ev) {
		return nil
	}

	// Process OnExportEvent hooks
	for _, f := range e.opts.OnExportEvent {
		stop, err := f.OnExportEvent(ctx, ev, e.encoder)
		if err != nil {
			e.logger.WithError(err).Warn("OnExportEvent failed")
		}
		if stop {
			// abort exporter pipeline by returning early but do not prevent
			// other OnDecodedEvent hooks from firing
			return nil
		}
	}

	res := e.eventToExportEvent(ev)
	if res == nil {
		return nil
	}
	return e.encoder.Encode(res)
}

// Stop implements the FlowLogExporter interface.
func (e *exporter) Stop() error {
	e.logger.Debug("hubble flow exporter stopping")
	if e.writer == nil {
		// Already stoppped
		return nil
	}
	err := e.writer.Close()
	e.writer = nil
	return err
}

// eventToExportEvent converts Event to ExportEvent.
func (e *exporter) eventToExportEvent(event *v1.Event) *observerpb.ExportEvent {
	switch ev := event.Event.(type) {
	case *flowpb.Flow:
		if e.opts.FieldMask.Active() {
			e.opts.FieldMask.Copy(e.flow.ProtoReflect(), ev.ProtoReflect())
			ev = e.flow
		}
		return &observerpb.ExportEvent{
			Time:     ev.GetTime(),
			NodeName: ev.GetNodeName(),
			ResponseTypes: &observerpb.ExportEvent_Flow{
				Flow: ev,
			},
		}
	case *flowpb.LostEvent:
		return &observerpb.ExportEvent{
			Time:     event.Timestamp,
			NodeName: nodeTypes.GetName(),
			ResponseTypes: &observerpb.ExportEvent_LostEvents{
				LostEvents: ev,
			},
		}
	case *flowpb.AgentEvent:
		return &observerpb.ExportEvent{
			Time:     event.Timestamp,
			NodeName: nodeTypes.GetName(),
			ResponseTypes: &observerpb.ExportEvent_AgentEvent{
				AgentEvent: ev,
			},
		}
	case *flowpb.DebugEvent:
		return &observerpb.ExportEvent{
			Time:     event.Timestamp,
			NodeName: nodeTypes.GetName(),
			ResponseTypes: &observerpb.ExportEvent_DebugEvent{
				DebugEvent: ev,
			},
		}
	default:
		return nil
	}
}
<<<<<<< HEAD

func (e *exporter) Stop() error {
	if e.writer == nil {
		// Already stoppped
		return nil
	}
	err := e.writer.Close()
	e.writer = nil
	return err
}

// OnDecodedEvent checks if the event passes the filter.
// If context was cancelled, it calls Stop() and stops processing events.
//func (e *exporter) OnDecodedEvent(_ context.Context, ev *v1.Event) (bool, error) {
//	select {
//	case <-e.ctx.Done():
//		return false, e.Stop()
//	default:
//	}
//	if !filters.Apply(e.opts.AllowList, e.opts.DenyList, ev) {
//		return false, nil
//	}
//	res := e.eventToExportEvent(ev)
//	if res == nil {
//		return false, nil
//	}
//	return false, e.encoder.Encode(res)
//}

func (e *exporter) OnDecodedEvent(_ context.Context, ev *v1.Event) (bool, error) {
	switch event := ev.Event.(type) {
	case *flowpb.Flow:
		uuid := event.GetUuid()
		hs := fnv.New32a()
		hs.Write([]byte(uuid))
		worker_id := int(hs.Sum32() % 100)
		e.logger.Debugf("OnDevocedEvent: ch [%d]", worker_id)
		e.logger.Infof("OnDevocedEvent: ch [%d]", worker_id)
		e.evch[worker_id] <- ev
	default:
		e.logger.Infof("OnDevocedEvent: ch default")
		e.evch[0] <- ev
	}

	return false, nil
}

func (e *exporter) DecodeEvent(evc chan *v1.Event) {
	for ev := range evc {
		if !filters.Apply(e.opts.AllowList, e.opts.DenyList, ev) {
			continue
		}
		e.eventToExportEvent(ev)
	}
}
=======
>>>>>>> upstream/main
