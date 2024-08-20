// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"os"

	"github.com/cilium/lumberjack/v2"
	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/hubble/filters"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// exporter is an implementation of OnDecodedEvent interface that writes Hubble events to a file.
type exporter struct {
	FlowLogExporter
	ctx     context.Context
	logger  logrus.FieldLogger
	encoder *json.Encoder
	writer  io.WriteCloser
	flow    *flowpb.Flow

	evch []chan *v1.Event
	opts exporteroption.Options
}

// NewExporter initializes an exporter.
func NewExporter(
	ctx context.Context,
	logger logrus.FieldLogger,
	options ...exporteroption.Option) (*exporter, error) {
	opts := exporteroption.Default // start with defaults
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	logger.WithField("options", opts).Info("Configuring Hubble event exporter")
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
}

// newExporter let's you supply your own WriteCloser for tests.
func newExporter(ctx context.Context, logger logrus.FieldLogger, writer io.WriteCloser, opts exporteroption.Options) (*exporter, error) {
	encoder := json.NewEncoder(writer)
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
		ctx:     ctx,
		logger:  logger,
		encoder: encoder,
		writer:  writer,
		flow:    flow,
		opts:    opts,
		evch:    ch,
	}, nil
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
