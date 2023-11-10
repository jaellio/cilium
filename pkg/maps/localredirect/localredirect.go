package localredirect

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName = "cilium_localredirect"
	// Flow aggregate is per Pod, so same size as Endpoint map.
	MapSize = lxcmap.MaxEntries
)

type LocalRedirectKey struct {
	Id uint64 `align:"id"`
}

func (k *LocalRedirectKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *LocalRedirectKey) New() bpf.MapKey            { return &LocalRedirectKey{} }
func (k *LocalRedirectKey) String() string             { return fmt.Sprintf("%x", int(k.Id)) }
func (k *LocalRedirectKey) DeepCopyMapKey() bpf.MapKey { return &LocalRedirectKey{k.Id} }

type LocalRedirectInfo struct {
	IfIndex uint16        `align:"ifindex"`
	IfMac   types.MACAddr `align:"ifmac"`
}

func (v *LocalRedirectInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (k *LocalRedirectInfo) New() bpf.MapValue           { return &LocalRedirectInfo{} }
func (v *LocalRedirectInfo) String() string              { return fmt.Sprintf("%d/% x", int(v.IfIndex), v.IfMac) }
func (v *LocalRedirectInfo) DeepCopyMapValue() bpf.MapValue {
	return &LocalRedirectInfo{v.IfIndex, v.IfMac}
}

var LocalRedirectMap = bpf.NewMap(
	MapName,
	ebpf.Hash,
	&LocalRedirectKey{},
	&LocalRedirectInfo{},
	MapSize,
	bpf.BPF_F_NO_PREALLOC,
).WithCache().WithPressureMetric()
