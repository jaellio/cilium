package hbone

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/vishvananda/netlink"
	"net"
	"net/netip"
	"time"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "hbone")
)

const (
	listenPort = 15001
)

// Agent needs to be initialized with Init(). In Init(), the Wireguard tunnel
// device will be created and the proper routes set.  During Init(), existing
// peer keys are placed into `restoredPubKeys`.  Once RestoreFinished() is
// called obsolete keys and peers are removed.  UpdatePeer() inserts or updates
// the public key of peer discovered via the node manager.
type Agent struct {
	lock.RWMutex
	ipCache         *ipcache.IPCache
	listenPort      int
	listener        net.Listener
	epManager       endpointmanager.EndpointManager
	pushChannel     chan Push
	localCiliumNode k8s.LocalCiliumNodeResource
}

type Push struct{}

func NewAgent() (*Agent, error) {
	log.Infof("howardjohn: creating hbone agent")
	return &Agent{
		listenPort:  listenPort,
		pushChannel: make(chan Push, 1),
	}, nil
}

// Close is called when the agent stops
func (a *Agent) Close() error {
	a.RLock()
	defer a.RUnlock()

	return nil
}

//Current state: we get the packets, but do nothing with them. Need to establish the other end, etc.

func (a *Agent) Init(ipcache *ipcache.IPCache, epmanager endpointmanager.EndpointManager, localNode k8s.LocalCiliumNodeResource) error {
	addIPCacheListener := false
	a.Lock()
	a.localCiliumNode = localNode
	a.ipCache = ipcache
	a.epManager = epmanager
	defer func() {
		// IPCache will call back into OnIPIdentityCacheChange which requires
		// us to release a.mutex before we can add ourself as a listener.
		a.Unlock()
		if addIPCacheListener {
			a.ipCache.AddListener(a)
		}
	}()
	if err := a.SetupServer(); err != nil {
		return err
	}
	// this is read by the defer statement above
	addIPCacheListener = true
	if err := a.SetupDevice(); err != nil {
		return err
	}

	return nil
}

func (a *Agent) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
	oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	log.Infof("IP cache changed")
	select {
	case a.pushChannel <- Push{}:
	default:
		log.Infof("push channel full, dropping")
	}
}

func (a *Agent) OnIPIdentityCacheGC() {
	log.Infof("IP cache GC")
}

func (a *Agent) SetupDevice() error {
	ztunnelIP := net.ParseIP(a.FetchZtunnelIP().String())

	inbnd := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name: InboundTun,
		},
		ID:     InboundTunVNI,
		Remote: ztunnelIP,
		Dport:  GenevePort,
	}
	_ = netlink.LinkDel(inbnd)
	log.Debugf("Building inbound tunnel: %+v", inbnd)

	if err := netlink.LinkAdd(inbnd); err != nil {
		return fmt.Errorf("failed to add inbound tunnel: %v", err)
	}
	if err := netlink.AddrAdd(inbnd, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP(InboundTunIP),
			Mask: net.CIDRMask(TunPrefix, 32),
		},
	}); err != nil {
		return fmt.Errorf("failed to add inbound tunnel address: %v", err)
	}
	if err := netlink.LinkSetUp(inbnd); err != nil {
		return fmt.Errorf("failed to set inbound tunnel up: %v", err)
	}

	outbnd := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name: OutboundTun,
		},
		ID:     OutboundTunVNI,
		Remote: ztunnelIP,
		Dport:  GenevePort,
	}
	_ = netlink.LinkDel(outbnd)
	log.Debugf("Building outbound tunnel: %+v", outbnd)

	if err := netlink.LinkAdd(outbnd); err != nil {
		return fmt.Errorf("failed to add outbound tunnel: %v", err)
	}
	if err := netlink.AddrAdd(outbnd, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP(OutboundTunIP),
			Mask: net.CIDRMask(TunPrefix, 32),
		},
	}); err != nil {
		return fmt.Errorf("failed to add outbound tunnel address: %v", err)
	}
	if err := netlink.LinkSetUp(outbnd); err != nil {
		return fmt.Errorf("failed to set inbound tunnel up: %v", err)
	}
	for _, dev := range []string{InboundTun, OutboundTun} {
		if err := sysctl.Disable(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", dev)); err != nil {
			return fmt.Errorf("failed to disable rp_filter: %w", err)
		}
		if err := sysctl.Enable(fmt.Sprintf("net.ipv4.conf.%s.accept_local", dev)); err != nil {
			return fmt.Errorf("failed to enable accept_local: %w", err)
		}
	}
	return nil
}

func (a *Agent) getNodeLocalName() (string, net.IP) {
	v, _ := a.localCiliumNode.Store(context.Background())
	n := v.List()[0]
	var ip string
	for _, nn := range n.Spec.Addresses {
		if nn.Type == addressing.NodeInternalIP {
			ip = nn.IP
		}
	}
	return n.Name, net.ParseIP(ip)
}

func (a *Agent) FetchZtunnelIP() netip.Addr {
	nodeName, nodeIP := a.getNodeLocalName()
	iter := 0
	a.ipCache.RLock()
	defer a.ipCache.RUnlock()
	log.Infof("synced? %v", a.ipCache.Synchronized())
	return netip.Addr{}

	cidrs := a.ipCache.LookupByHostRLocked(nodeIP, nil)
	log.Infof("Got CIDRs %v", cidrs)
	for _, cidr := range cidrs {
		addr := netip.MustParseAddr(cidr.IP.String())
		metaLabels := a.ipCache.GetMetadataLabelsByIP(addr)
		log.Infof("cidr %v labels %v", cidr, metaLabels)
		for k, v := range metaLabels {
			if k == "k8s:io.cilium.k8s.policy.serviceaccount" && v.Value == "ztunnel" {
				return addr
			}
		}
	}
	panic("no ztunnel IP")
	for len(a.epManager.GetEndpoints()) == 0 {
		log.Infof("endpoints empty...")
		time.Sleep(time.Second)
		iter++
		if iter > 15 {
			panic("never synced")
		}
	}
	log.Infof("got node %v", nodeName)
	for _, ep := range a.epManager.GetEndpoints() {
		p := ep.GetPod()
		ns := p.Namespace
		sa := p.Spec.ServiceAccountName
		node := p.Spec.NodeName
		log.Infof("check pod %v/%v/%v", ns, sa, node)
		if ns != "istio-system" {
			continue
		}
		if sa != "ztunnel" {
			continue
		}
		if node != nodeName {
			continue
		}
		log.Infof("got ztunnel IP %v", ep.IPv4)
		return ep.IPv4
	}
	panic("no ztunnel IP")
	return netip.Addr{}
}

const (
	InboundTun  = "istioin"
	OutboundTun = "istioout"

	GenevePort = uint16(6081)

	InboundTunVNI  = uint32(1000)
	OutboundTunVNI = uint32(1001)

	InboundTunIP         = "192.168.126.1"
	ZTunnelInboundTunIP  = "192.168.126.2"
	OutboundTunIP        = "192.168.127.1"
	ZTunnelOutboundTunIP = "192.168.127.2"
	TunPrefix            = 30
)
