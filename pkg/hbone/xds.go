package hbone

import (
	"errors"
	"fmt"
	"github.com/cilium/cilium/pkg/hbone/workloadapi"
	"github.com/cilium/cilium/pkg/logging/logfields"
	discovery "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"io"
	"k8s.io/apimachinery/pkg/util/sets"
	"net"
	"net/netip"
	"strings"
)

func (a *Agent) SetupServer() error {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.listenPort))
	if err != nil {
		return err
	}
	a.listener = l
	grpcServer := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, a)
	reflection.Register(grpcServer)

	go func() {
		log.Infof("HBONE: Starting xDS gRPC server listening on %s", a.listener.Addr())
		if err := grpcServer.Serve(a.listener); err != nil && !errors.Is(err, net.ErrClosed) {
			log.WithError(err).Fatal("Envoy: Failed to serve xDS gRPC API")
		}
	}()
	return nil
}

func (a *Agent) StreamAggregatedResources(server discovery.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	// Only Delta
	return errors.New("not implemented")
}

var (
	// grpcCanceled is the string prefix of any gRPC error related
	// to the stream being canceled. Ignore the description, as it
	// is derived from the client and may vary, while the code is
	// set by the gRPC library we link with.
	//
	// Ref. vendor/google.golang.org/grpc/status/status.go:
	// return fmt.Sprintf("rpc error: code = %s desc = %s", codes.Code(p.GetCode()), p.GetMessage())
	grpcCanceled = fmt.Sprintf("rpc error: code = %s", codes.Canceled.String())
)

func (a *Agent) DeltaAggregatedResources(stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	reqCh := make(chan *discovery.DeltaDiscoveryRequest)

	stopRecv := make(chan struct{})
	defer close(stopRecv)

	streamLog := log.WithField(logfields.XDSStreamID, 1)
	go func() {
		defer close(reqCh)
		for {
			req, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					streamLog.Debug("xDS stream closed")
				} else if strings.HasPrefix(err.Error(), grpcCanceled) {
					streamLog.WithError(err).Debug("xDS stream canceled")
				} else {
					streamLog.WithError(err).Error("error while receiving request from xDS stream")
				}
				return
			}
			// This should be only set for the first request. The node id may not be set - for example malicious clients.
			select {
			case reqCh <- req:
			case <-stream.Context().Done():
				log.Infof("ADS: terminated with stream closed")
				return
			}
		}
	}()

	return a.processRequestStream(streamLog, stream, reqCh)
}

const WorkloadType = "type.googleapis.com/istio.workload.Workload"

func (a *Agent) processRequestStream(streamLog *logrus.Entry, stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer, ch chan *discovery.DeltaDiscoveryRequest) error {
	version := 0
	subs := sets.New[string]()
	for {
		version++
		send := func(names []string) error {
			resp := &discovery.DeltaDiscoveryResponse{
				TypeUrl:           WorkloadType,
				SystemVersionInfo: fmt.Sprint(version),
				Nonce:             fmt.Sprint(version),
			}
			// Push new additions
			for _, name := range names {
				wl := a.buildWorkload(name)
				if wl == nil {
					resp.RemovedResources = append(resp.RemovedResources, name)
				} else {
					resp.Resources = append(resp.Resources, &discovery.Resource{
						Name:     name,
						Version:  fmt.Sprint(version),
						Resource: wl,
					})
				}
			}
			return stream.Send(resp)
		}
		select {
		case req, ok := <-ch:
			if !ok {
				return fmt.Errorf("done")
			}
			subs = subs.Insert(req.ResourceNamesSubscribe...).Delete(req.ResourceNamesUnsubscribe...)
			// Push new additions
			if err := send(req.ResourceNamesSubscribe); err != nil {
				return err
			}
		case <-a.pushChannel:
			// Push everything. TODO: incremental
			if err := send(subs.UnsortedList()); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (a *Agent) buildWorkload(raw string) *anypb.Any {
	ip, _ := netip.ParseAddr(raw)
	meta := a.ipCache.GetK8sMetadata(ip)
	if meta == nil {
		return nil
	}
	wl := &workloadapi.Workload{
		Addresses:      [][]byte{ip.AsSlice()},
		TunnelProtocol: workloadapi.TunnelProtocol_HBONE,
		//Node:           "",
	}
	lbls := a.ipCache.GetMetadataLabelsByIP(ip)
	for k, v := range lbls {
		if k == "k8s:io.cilium.k8s.policy.serviceaccount" {
			wl.ServiceAccount = v.Value
		}
	}
	if meta != nil {
		wl.Name = meta.PodName
		wl.Namespace = meta.Namespace
	}
	wl.Uid = "Kubernetes" + "//" + "Pod/" + wl.Namespace + "/" + wl.Name
	return toAny(wl)
}

func toAny(pb proto.Message) *anypb.Any {
	a, err := anypb.New(pb)
	if err != nil {
		panic(err.Error())
	}
	return a
}
