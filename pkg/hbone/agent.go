package hbone

import (
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"net"
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
	ipCache     *ipcache.IPCache
	listenPort  int
	listener    net.Listener
	epManager   endpointmanager.EndpointManager
	pushChannel chan Push
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

func (a *Agent) Init(ipcache *ipcache.IPCache, epmanager endpointmanager.EndpointManager) error {
	addIPCacheListener := false
	a.Lock()
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

	return nil
}

func (a *Agent) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
	oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	log.Infof("IP cache changed")
	a.pushChannel <- Push{}
}

func (a *Agent) OnIPIdentityCacheGC() {
	log.Infof("IP cache GC")
}
