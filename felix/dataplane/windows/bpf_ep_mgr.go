// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package windataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/logutils"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/xdp"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/ratelimited"
)

const jumpMapCleanupInterval = 10 * time.Second

type attachPoint interface {
	IfaceName() string
	JumpMapFDMapKey() string
	IsAttached() (bool, error)
	AttachProgram() (string, error)
	DetachProgram() error
	Log() *log.Entry
}

type bpfDataplane interface {
	ensureStarted()
	ensureProgramAttached(ap attachPoint) (bpf.MapFD, error)
	ensureNoProgram(ap attachPoint) error
	updatePolicyProgram(jumpMapFD bpf.MapFD, rules polprog.Rules) error
	removePolicyProgram(jumpMapFD bpf.MapFD) error
	setAcceptLocal(iface string, val bool) error
}

type bpfInterface struct {
	// info contains the information about the interface sent to us from external sources. For example,
	// the ID of the controlling workload interface and our current expectation of its "oper state".
	// When the info changes, we mark the interface dirty and refresh its dataplane state.
	info bpfInterfaceInfo
	// dpState contains the dataplane state that we've derived locally.  It caches the result of updating
	// the interface (so changes to dpState don't cause the interface to be marked dirty).
	dpState bpfInterfaceState
}

type bpfInterfaceInfo struct {
	ifaceIsUp  bool
	endpointID *proto.WorkloadEndpointID
}

type bpfInterfaceState struct {
	jumpMapFDs map[string]bpf.MapFD
}

type bpfEndpointManager struct {
	// Main store of information about interfaces; indexed on interface name.
	ifacesLock  sync.Mutex
	nameToIface map[string]bpfInterface

	allWEPs        map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	happyWEPs      map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	happyWEPsDirty bool
	policies       map[proto.PolicyID]*proto.Policy
	profiles       map[proto.ProfileID]*proto.Profile

	// Indexes
	policiesToWorkloads map[proto.PolicyID]set.Set  /*proto.WorkloadEndpointID*/
	profilesToWorkloads map[proto.ProfileID]set.Set /*proto.WorkloadEndpointID*/

	dirtyIfaceNames set.Set

	bpfLogLevel string
	hostname    string
	hostIP      net.IP

	ipSetIDAlloc *idalloc.IDAllocator

	bpfMapContext *bpf.MapContext

	startupOnce      sync.Once
	mapCleanupRunner *ratelimited.Runner

	// onStillAlive is called from loops to reset the watchdog.
	onStillAlive func()

	// HEP processing.
	hostIfaceToEpMap     map[string]proto.HostEndpoint
	wildcardHostEndpoint proto.HostEndpoint
	wildcardExists       bool

	// UT-able BPF dataplane interface.
	dp bpfDataplane

	ifaceToIpMap map[string]net.IP
	opReporter   logutils.OpRecorder

	// XDP
	xdpModes []bpf.XDPMode
}

func newBPFEndpointManager(
	config *Config,
	bpfMapContext *bpf.MapContext,
	ipSetIDAlloc *idalloc.IDAllocator,
	livenessCallback func(),
	opReporter logutils.OpRecorder,
) *bpfEndpointManager {
	if livenessCallback == nil {
		livenessCallback = func() {}
	}
	m := &bpfEndpointManager{
		allWEPs:             map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		happyWEPs:           map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		happyWEPsDirty:      true,
		policies:            map[proto.PolicyID]*proto.Policy{},
		profiles:            map[proto.ProfileID]*proto.Profile{},
		nameToIface:         map[string]bpfInterface{},
		policiesToWorkloads: map[proto.PolicyID]set.Set{},
		profilesToWorkloads: map[proto.ProfileID]set.Set{},
		dirtyIfaceNames:     set.New(),
		bpfLogLevel:         config.BPFLogLevel,
		hostname:            config.Hostname,
		ipSetIDAlloc:        ipSetIDAlloc,
		bpfMapContext:       bpfMapContext,
		mapCleanupRunner: ratelimited.NewRunner(jumpMapCleanupInterval, func(ctx context.Context) {
			log.Debug("Jump map cleanup triggered.")
			//TODO tc.CleanUpJumpMaps()
		}),
		onStillAlive:     livenessCallback,
		hostIfaceToEpMap: map[string]proto.HostEndpoint{},
		ifaceToIpMap:     map[string]net.IP{},
		opReporter:       opReporter,
	}

	// Clean all the files under /var/run/calico/bpf/prog to remove any information from the
	// previous execution of the bpf dataplane, and make sure the directory exists.
	bpf.CleanAttachedProgDir()

	// Normally this endpoint manager uses its own dataplane implementation, but we have an
	// indirection here so that UT can simulate the dataplane and test how it's called.
	m.dp = m
	return m
}

// withIface handles the bookkeeping for working with a particular bpfInterface value.  It
// * creates the value if needed
// * calls the giving callback with the value so it can be edited
// * if the bpfInterface's info field changes, it marks it as dirty
// * if the bpfInterface is now empty (no info or state), it cleans it up.
func (m *bpfEndpointManager) withIface(ifaceName string, fn func(iface *bpfInterface) (forceDirty bool)) {
	iface := m.nameToIface[ifaceName]
	ifaceCopy := iface
	dirty := fn(&iface)
	logCtx := log.WithField("name", ifaceName)

	var zeroIface bpfInterface
	if reflect.DeepEqual(iface, zeroIface) {
		logCtx.Debug("Interface info is now empty.")
		delete(m.nameToIface, ifaceName)
	} else {
		// Always store the result (rather than checking the dirty flag) because dirty only covers the info..
		m.nameToIface[ifaceName] = iface
	}

	dirty = dirty || iface.info != ifaceCopy.info

	if !dirty {
		return
	}

	logCtx.Debug("Marking iface dirty.")
	m.dirtyIfaceNames.Add(ifaceName)
}

func (m *bpfEndpointManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// Updates from the dataplane:

	// Updates from the datamodel:

	// Workloads.
	case *proto.WorkloadEndpointUpdate:
		m.onWorkloadEndpointUpdate(msg)
	case *proto.WorkloadEndpointRemove:
		m.onWorkloadEnpdointRemove(msg)
	// Policies.
	case *proto.ActivePolicyUpdate:
		m.onPolicyUpdate(msg)
	case *proto.ActivePolicyRemove:
		m.onPolicyRemove(msg)
	// Profiles.
	case *proto.ActiveProfileUpdate:
		m.onProfileUpdate(msg)
	case *proto.ActiveProfileRemove:
		m.onProfileRemove(msg)

	case *proto.HostMetadataUpdate:
		if msg.Hostname == m.hostname {
			log.WithField("HostMetadataUpdate", msg).Info("Host IP changed")
			ip := net.ParseIP(msg.Ipv4Addr)
			if ip != nil {
				m.hostIP = ip
				// Should be safe without the lock since there shouldn't be any active background threads
				// but taking it now makes us robust to refactoring.
				m.ifacesLock.Lock()
				for ifaceName := range m.nameToIface {
					m.dirtyIfaceNames.Add(ifaceName)
				}
				m.ifacesLock.Unlock()
			} else {
				log.WithField("HostMetadataUpdate", msg).Warn("Cannot parse IP, no change applied")
			}
		}
	}
}

// onWorkloadEndpointUpdate adds/updates the workload in the cache along with the index from active policy to
// workloads using that policy.
func (m *bpfEndpointManager) onWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate) {
	log.WithField("wep", msg.Endpoint).Debug("Workload endpoint update")
	wlID := *msg.Id
	oldWEP := m.allWEPs[wlID]
	m.removeWEPFromIndexes(wlID, oldWEP)

	wl := msg.Endpoint
	m.allWEPs[wlID] = wl
	m.addWEPToIndexes(wlID, wl)
	m.withIface(wl.Name, func(iface *bpfInterface) bool {
		iface.info.endpointID = &wlID
		return true // Force interface to be marked dirty in case policies changed.
	})
}

// onWorkloadEndpointRemove removes the workload from the cache and the index, which maps from policy to workload.
func (m *bpfEndpointManager) onWorkloadEnpdointRemove(msg *proto.WorkloadEndpointRemove) {
	wlID := *msg.Id
	log.WithField("id", wlID).Debug("Workload endpoint removed")
	oldWEP := m.allWEPs[wlID]
	m.removeWEPFromIndexes(wlID, oldWEP)
	delete(m.allWEPs, wlID)

	if m.happyWEPs[wlID] != nil {
		delete(m.happyWEPs, wlID)
		m.happyWEPsDirty = true
	}

	m.withIface(oldWEP.Name, func(iface *bpfInterface) bool {
		iface.info.endpointID = nil
		return false
	})
}

// onPolicyUpdate stores the policy in the cache and marks any endpoints using it dirty.
func (m *bpfEndpointManager) onPolicyUpdate(msg *proto.ActivePolicyUpdate) {
	polID := *msg.Id
	log.WithField("id", polID).Debug("Policy update")
	m.policies[polID] = msg.Policy
	m.markEndpointsDirty(m.policiesToWorkloads[polID], "policy")
}

// onPolicyRemove removes the policy from the cache and marks any endpoints using it dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onPolicyRemove(msg *proto.ActivePolicyRemove) {
	polID := *msg.Id
	log.WithField("id", polID).Debug("Policy removed")
	m.markEndpointsDirty(m.policiesToWorkloads[polID], "policy")
	delete(m.policies, polID)
	delete(m.policiesToWorkloads, polID)
}

// onProfileUpdate stores the profile in the cache and marks any endpoints that use it as dirty.
func (m *bpfEndpointManager) onProfileUpdate(msg *proto.ActiveProfileUpdate) {
	profID := *msg.Id
	log.WithField("id", profID).Debug("Profile update")
	m.profiles[profID] = msg.Profile
	m.markEndpointsDirty(m.profilesToWorkloads[profID], "profile")
}

// onProfileRemove removes the profile from the cache and marks any endpoints that were using it as dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onProfileRemove(msg *proto.ActiveProfileRemove) {
	profID := *msg.Id
	log.WithField("id", profID).Debug("Profile removed")
	m.markEndpointsDirty(m.profilesToWorkloads[profID], "profile")
	delete(m.profiles, profID)
	delete(m.profilesToWorkloads, profID)
}

func (m *bpfEndpointManager) markEndpointsDirty(ids set.Set, kind string) {
	if ids == nil {
		// Hear about the policy/profile before the endpoint.
		return
	}
	ids.Iter(func(item interface{}) error {
		switch id := item.(type) {
		case proto.WorkloadEndpointID:
			m.markExistingWEPDirty(id, kind)
		case string:
			if id == allInterfaces {
				for ifaceName := range m.nameToIface {
					if m.isWorkloadIface(ifaceName) {
						log.Debugf("Mark WEP iface dirty, for host-* endpoint %v change", kind)
						m.dirtyIfaceNames.Add(ifaceName)
					}
				}
			} else {
				log.Debugf("Mark host iface dirty, for host %v change", kind)
				m.dirtyIfaceNames.Add(id)
			}
		}
		return nil
	})
}

func (m *bpfEndpointManager) markExistingWEPDirty(wlID proto.WorkloadEndpointID, mapping string) {
	wep := m.allWEPs[wlID]
	if wep == nil {
		log.WithField("wlID", wlID).Panicf(
			"BUG: %s mapping points to unknown workload.", mapping)
	} else {
		m.dirtyIfaceNames.Add(wep.Name)
	}
}

func (m *bpfEndpointManager) CompleteDeferredWork() error {
	// Do one-off initialisation.
	m.dp.ensureStarted()

	m.applyProgramsToDirtyDataInterfaces()

	// Copy data from old map to the new map
	bpfmap.MigrateDataFromOldMap(m.bpfMapContext)
	return nil
}

func (m *bpfEndpointManager) applyProgramsToDirtyDataInterfaces() {
	var mutex sync.Mutex
	errs := map[string]error{}
	var wg sync.WaitGroup
	m.dirtyIfaceNames.Iter(func(item interface{}) error {
		iface := item.(string)
		if !m.isDataIface(iface) {
			log.WithField("iface", iface).Debug(
				"Ignoring interface that doesn't match the host data interface regex")
			return nil
		}
		if !m.ifaceIsUp(iface) {
			log.WithField("iface", iface).Debug("Ignoring interface that is down")
			return set.RemoveItem
		}

		m.opReporter.RecordOperation("update-data-iface")

		wg.Add(1)
		go func() {
			defer wg.Done()

			var hepPtr *proto.HostEndpoint
			if hep, hepExists := m.hostIfaceToEpMap[iface]; hepExists {
				hepPtr = &hep
			}
			err := m.attachXDPProgram(iface, hepPtr)
			mutex.Lock()
			errs[iface] = err
			mutex.Unlock()
		}()
		return nil
	})
	wg.Wait()
	m.dirtyIfaceNames.Iter(func(item interface{}) error {
		iface := item.(string)
		if !m.isDataIface(iface) {
			log.WithField("iface", iface).Debug(
				"Ignoring interface that doesn't match the host data interface regex")
			return nil
		}
		err := errs[iface]
		if err == nil {
			log.WithField("id", iface).Info("Applied program to host interface")
			return set.RemoveItem
		}
		if isLinkNotFoundError(err) {
			log.WithField("iface", iface).Debug(
				"Tried to apply BPF program to interface but the interface wasn't present.  " +
					"Will retry if it shows up.")
			return set.RemoveItem
		}
		log.WithField("iface", iface).WithError(err).Warn("Failed to apply policy to interface, will retry")
		return nil
	})
}

func isLinkNotFoundError(err error) bool {
	/*
		if errors.Is(err, tc.ErrDeviceNotFound) { // From the tc package.
			return true
		}
		if err.Error() == "Link not found" { // From netlink and friends.
			return true
		}
	*/
	return false
}

func (m *bpfEndpointManager) addHostPolicy(rules *polprog.Rules, hostEndpoint *proto.HostEndpoint, polDirection PolDirection) {

	// When there is applicable pre-DNAT policy that does not explicitly Allow or Deny traffic,
	// we continue on to subsequent tiers and normal or AoF policy.
	if len(hostEndpoint.PreDnatTiers) == 1 {
		rules.HostPreDnatTiers = m.extractTiers(hostEndpoint.PreDnatTiers[0], polDirection, NoEndTierDrop)
	}

	// When there is applicable apply-on-forward policy that does not explicitly Allow or Deny
	// traffic, traffic is dropped.
	if len(hostEndpoint.ForwardTiers) == 1 {
		rules.HostForwardTiers = m.extractTiers(hostEndpoint.ForwardTiers[0], polDirection, EndTierDrop)
	}

	// When there is applicable normal policy that does not explicitly Allow or Deny traffic,
	// traffic is dropped.
	if len(hostEndpoint.Tiers) == 1 {
		rules.HostNormalTiers = m.extractTiers(hostEndpoint.Tiers[0], polDirection, EndTierDrop)
	}
	rules.HostProfiles = m.extractProfiles(hostEndpoint.ProfileIds, polDirection)
}

func (m *bpfEndpointManager) ifaceIsUp(ifaceName string) (up bool) {
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()
	m.withIface(ifaceName, func(iface *bpfInterface) bool {
		up = iface.info.ifaceIsUp
		return false
	})
	return
}

func (m *bpfEndpointManager) attachXDPProgram(ifaceName string, ep *proto.HostEndpoint) error {
	ap := xdp.AttachPoint{
		Iface:    ifaceName,
		LogLevel: m.bpfLogLevel,
		Modes:    m.xdpModes,
	}

	if ep != nil && len(ep.UntrackedTiers) == 1 {
		jumpMapFD, err := m.dp.ensureProgramAttached(&ap)
		if err != nil {
			return err
		}

		ap.Log().Debugf("Building program for untracked policy hep=%v jumpMapFD=%v", ep.Name, jumpMapFD)
		rules := polprog.Rules{
			ForHostInterface: true,
			HostNormalTiers:  m.extractTiers(ep.UntrackedTiers[0], PolDirnIngress, false),
			ForXDP:           true,
		}
		ap.Log().Debugf("Rules: %v", rules)
		return m.dp.updatePolicyProgram(jumpMapFD, rules)
	} else {
		return m.dp.ensureNoProgram(&ap)
	}
}

// PolDirection is the Calico datamodel direction of policy.  On a host endpoint, ingress is towards the host.
// On a workload endpoint, ingress is towards the workload.
type PolDirection int

const (
	PolDirnIngress PolDirection = iota
	PolDirnEgress
)

func (polDirection PolDirection) Inverse() PolDirection {
	if polDirection == PolDirnIngress {
		return PolDirnEgress
	}
	return PolDirnIngress
}

const EndTierDrop = true
const NoEndTierDrop = false

func (m *bpfEndpointManager) extractTiers(tier *proto.TierInfo, direction PolDirection, endTierDrop bool) (rTiers []polprog.Tier) {
	if tier == nil {
		return
	}

	directionalPols := tier.IngressPolicies
	if direction == PolDirnEgress {
		directionalPols = tier.EgressPolicies
	}

	if len(directionalPols) > 0 {
		polTier := polprog.Tier{
			Name:     tier.Name,
			Policies: make([]polprog.Policy, len(directionalPols)),
		}

		for i, polName := range directionalPols {
			pol := m.policies[proto.PolicyID{Tier: tier.Name, Name: polName}]
			var prules []*proto.Rule
			if direction == PolDirnIngress {
				prules = pol.InboundRules
			} else {
				prules = pol.OutboundRules
			}
			policy := polprog.Policy{
				Name:  polName,
				Rules: make([]polprog.Rule, len(prules)),
			}

			for ri, r := range prules {
				policy.Rules[ri] = polprog.Rule{
					Rule: r,
				}
			}

			polTier.Policies[i] = policy
		}

		if endTierDrop {
			polTier.EndAction = polprog.TierEndDeny
		} else {
			polTier.EndAction = polprog.TierEndPass
		}

		rTiers = append(rTiers, polTier)
	}
	return
}

func (m *bpfEndpointManager) extractProfiles(profileNames []string, direction PolDirection) (rProfiles []polprog.Profile) {
	if count := len(profileNames); count > 0 {
		rProfiles = make([]polprog.Profile, count)

		for i, profName := range profileNames {
			prof := m.profiles[proto.ProfileID{Name: profName}]
			var prules []*proto.Rule
			if direction == PolDirnIngress {
				prules = prof.InboundRules
			} else {
				prules = prof.OutboundRules
			}
			profile := polprog.Profile{
				Name:  profName,
				Rules: make([]polprog.Rule, len(prules)),
			}

			for ri, r := range prules {
				profile.Rules[ri] = polprog.Rule{
					Rule: r,
				}
			}

			rProfiles[i] = profile
		}
	}
	return
}

func (m *bpfEndpointManager) extractRules(tier *proto.TierInfo, profileNames []string, direction PolDirection) polprog.Rules {
	var r polprog.Rules

	// When there is applicable normal policy that does not explicitly Allow or Deny traffic,
	// traffic is dropped.
	r.Tiers = m.extractTiers(tier, direction, EndTierDrop)

	r.Profiles = m.extractProfiles(profileNames, direction)

	return r
}

func (m *bpfEndpointManager) isWorkloadIface(iface string) bool {
	return false
}

func (m *bpfEndpointManager) isDataIface(iface string) bool {
	return false
}

func (m *bpfEndpointManager) addWEPToIndexes(wlID proto.WorkloadEndpointID, wl *proto.WorkloadEndpoint) {
	for _, t := range wl.Tiers {
		m.addPolicyToEPMappings(t.IngressPolicies, wlID)
		m.addPolicyToEPMappings(t.EgressPolicies, wlID)
	}
	m.addProfileToEPMappings(wl.ProfileIds, wlID)
}

func (m *bpfEndpointManager) addPolicyToEPMappings(polNames []string, id interface{}) {
	for _, pol := range polNames {
		polID := proto.PolicyID{
			Tier: "default",
			Name: pol,
		}
		if m.policiesToWorkloads[polID] == nil {
			m.policiesToWorkloads[polID] = set.New()
		}
		m.policiesToWorkloads[polID].Add(id)
	}
}

func (m *bpfEndpointManager) addProfileToEPMappings(profileIds []string, id interface{}) {
	for _, profName := range profileIds {
		profID := proto.ProfileID{Name: profName}
		profSet := m.profilesToWorkloads[profID]
		if profSet == nil {
			profSet = set.New()
			m.profilesToWorkloads[profID] = profSet
		}
		profSet.Add(id)
	}
}

func (m *bpfEndpointManager) removeWEPFromIndexes(wlID proto.WorkloadEndpointID, wep *proto.WorkloadEndpoint) {
	if wep == nil {
		return
	}

	for _, t := range wep.Tiers {
		m.removePolicyToEPMappings(t.IngressPolicies, wlID)
		m.removePolicyToEPMappings(t.EgressPolicies, wlID)
	}

	m.removeProfileToEPMappings(wep.ProfileIds, wlID)

	m.withIface(wep.Name, func(iface *bpfInterface) bool {
		iface.info.endpointID = nil
		return false
	})
}

func (m *bpfEndpointManager) removePolicyToEPMappings(polNames []string, id interface{}) {
	for _, pol := range polNames {
		polID := proto.PolicyID{
			Tier: "default",
			Name: pol,
		}
		polSet := m.policiesToWorkloads[polID]
		if polSet == nil {
			continue
		}
		polSet.Discard(id)
		if polSet.Len() == 0 {
			// Defensive; we also clean up when the profile is removed.
			delete(m.policiesToWorkloads, polID)
		}
	}
}

func (m *bpfEndpointManager) removeProfileToEPMappings(profileIds []string, id interface{}) {
	for _, profName := range profileIds {
		profID := proto.ProfileID{Name: profName}
		profSet := m.profilesToWorkloads[profID]
		if profSet == nil {
			continue
		}
		profSet.Discard(id)
		if profSet.Len() == 0 {
			// Defensive; we also clean up when the policy is removed.
			delete(m.profilesToWorkloads, profID)
		}
	}
}

func (m *bpfEndpointManager) OnHEPUpdate(hostIfaceToEpMap map[string]proto.HostEndpoint) {
	if m == nil {
		return
	}

	log.Debugf("HEP update from generic endpoint manager: %v", hostIfaceToEpMap)

	// Pre-process the map for the host-* endpoint: if there is a host-* endpoint, any host
	// interface without its own HEP should use the host-* endpoint's policy.
	wildcardHostEndpoint, wildcardExists := hostIfaceToEpMap[allInterfaces]
	if wildcardExists {
		log.Info("Host-* endpoint is configured")
		for ifaceName := range m.nameToIface {
			if _, specificExists := hostIfaceToEpMap[ifaceName]; m.isDataIface(ifaceName) && !specificExists {
				log.Infof("Use host-* endpoint policy for %v", ifaceName)
				hostIfaceToEpMap[ifaceName] = wildcardHostEndpoint
			}
		}
		delete(hostIfaceToEpMap, allInterfaces)
	}

	// If there are parts of proto.HostEndpoint that do not affect us, we could mask those out
	// here so that they can't cause spurious updates - at the cost of having different
	// proto.HostEndpoint data here than elsewhere.  For example, the ExpectedIpv4Addrs and
	// ExpectedIpv6Addrs fields.  But currently there are no fields that are sufficiently likely
	// to change as to make this worthwhile.

	// If the host-* endpoint is changing, mark all workload interfaces as dirty.
	if (wildcardExists != m.wildcardExists) || !reflect.DeepEqual(wildcardHostEndpoint, m.wildcardHostEndpoint) {
		log.Infof("Host-* endpoint is changing; was %v, now %v", m.wildcardHostEndpoint, wildcardHostEndpoint)
		m.removeHEPFromIndexes(allInterfaces, &m.wildcardHostEndpoint)
		m.wildcardHostEndpoint = wildcardHostEndpoint
		m.wildcardExists = wildcardExists
		m.addHEPToIndexes(allInterfaces, &wildcardHostEndpoint)
		for ifaceName := range m.nameToIface {
			if m.isWorkloadIface(ifaceName) {
				log.Info("Mark WEP iface dirty, for host-* endpoint change")
				m.dirtyIfaceNames.Add(ifaceName)
			}
		}
	}

	// Loop through existing host endpoints, in case they are changing or disappearing.
	for ifaceName, existingEp := range m.hostIfaceToEpMap {
		newEp, stillExists := hostIfaceToEpMap[ifaceName]
		if stillExists && reflect.DeepEqual(newEp, existingEp) {
			log.Debugf("No change to host endpoint for ifaceName=%v", ifaceName)
		} else {
			m.removeHEPFromIndexes(ifaceName, &existingEp)
			if stillExists {
				log.Infof("Host endpoint changing for ifaceName=%v", ifaceName)
				m.addHEPToIndexes(ifaceName, &newEp)
				m.hostIfaceToEpMap[ifaceName] = newEp
			} else {
				log.Infof("Host endpoint deleted for ifaceName=%v", ifaceName)
				delete(m.hostIfaceToEpMap, ifaceName)
			}
			m.dirtyIfaceNames.Add(ifaceName)
		}
		delete(hostIfaceToEpMap, ifaceName)
	}

	// Now anything remaining in hostIfaceToEpMap must be a new host endpoint.
	for ifaceName, newEp := range hostIfaceToEpMap {
		if !m.isDataIface(ifaceName) {
			log.Warningf("Host endpoint configured for ifaceName=%v, but that doesn't match BPFDataIfacePattern; ignoring", ifaceName)
			continue
		}
		log.Infof("Host endpoint added for ifaceName=%v", ifaceName)
		m.addHEPToIndexes(ifaceName, &newEp)
		m.hostIfaceToEpMap[ifaceName] = newEp
		m.dirtyIfaceNames.Add(ifaceName)
	}
}

func (m *bpfEndpointManager) addHEPToIndexes(ifaceName string, ep *proto.HostEndpoint) {
	for _, tiers := range [][]*proto.TierInfo{ep.Tiers, ep.UntrackedTiers, ep.PreDnatTiers, ep.ForwardTiers} {
		for _, t := range tiers {
			m.addPolicyToEPMappings(t.IngressPolicies, ifaceName)
			m.addPolicyToEPMappings(t.EgressPolicies, ifaceName)
		}
	}
	m.addProfileToEPMappings(ep.ProfileIds, ifaceName)
}

func (m *bpfEndpointManager) removeHEPFromIndexes(ifaceName string, ep *proto.HostEndpoint) {
	for _, tiers := range [][]*proto.TierInfo{ep.Tiers, ep.UntrackedTiers, ep.PreDnatTiers, ep.ForwardTiers} {
		for _, t := range tiers {
			m.removePolicyToEPMappings(t.IngressPolicies, ifaceName)
			m.removePolicyToEPMappings(t.EgressPolicies, ifaceName)
		}
	}

	m.removeProfileToEPMappings(ep.ProfileIds, ifaceName)
}

// Not used on Windows right now.
func (m *bpfEndpointManager) setAcceptLocal(iface string, val bool) error {
	return nil
}

func (m *bpfEndpointManager) ensureStarted() {
	m.startupOnce.Do(func() {
		log.Info("Starting map cleanup runner.")
		m.mapCleanupRunner.Start(context.Background())
	})
}

// Ensure TC/XDP program is attached to the specified interface and return its jump map FD.
func (m *bpfEndpointManager) ensureProgramAttached(ap attachPoint) (bpf.MapFD, error) {
	jumpMapFD := m.getJumpMapFD(ap)
	if jumpMapFD != 0 {
		ap.Log().Debugf("Known jump map fd=%v", jumpMapFD)
		if attached, err := ap.IsAttached(); err != nil {
			return jumpMapFD, fmt.Errorf("failed to check if interface %s had BPF program; %w", ap.IfaceName(), err)
		} else if !attached {
			// BPF program is missing; maybe we missed a notification of the interface being recreated?
			// Close the now-defunct jump map.
			log.WithField("iface", ap.IfaceName()).Info(
				"Detected that BPF program no longer attached to interface.")
			err := jumpMapFD.Close()
			if err != nil {
				log.WithError(err).Warn("Failed to close jump map FD. Ignoring.")
			}
			m.setJumpMapFD(ap, 0)
			jumpMapFD = 0 // Trigger program to be re-added below.
		}
	}

	if jumpMapFD == 0 {
		ap.Log().Info("Need to attach program")
		// We don't have a program attached to this interface yet, attach one now.
		progID, err := ap.AttachProgram()
		if err != nil {
			return 0, err
		}

		jumpMapFD, err = FindJumpMap(progID, ap.IfaceName())
		if err != nil {
			return 0, fmt.Errorf("failed to look up jump map: %w", err)
		}
		m.setJumpMapFD(ap, jumpMapFD)
	}

	return jumpMapFD, nil
}

// Ensure that the specified interface does not have our XDP program, in any mode, but avoid
// touching anyone else's XDP program(s).
func (m *bpfEndpointManager) ensureNoProgram(ap attachPoint) error {

	// Clean up jump map FD if there is one.
	jumpMapFD := m.getJumpMapFD(ap)
	if jumpMapFD != 0 {
		// Close the jump map FD.
		if err := jumpMapFD.Close(); err == nil {
			m.setJumpMapFD(ap, 0)
		} else {
			// Return error so as to trigger a retry.
			return fmt.Errorf("Failed to close jump map FD %v: %w", jumpMapFD, err)
		}
	}

	// Ensure interface does not have our XDP program attached in any mode.
	return ap.DetachProgram()
}

func (m *bpfEndpointManager) getJumpMapFD(ap attachPoint) (fd bpf.MapFD) {
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()
	m.withIface(ap.IfaceName(), func(iface *bpfInterface) bool {
		if iface.dpState.jumpMapFDs != nil {
			fd = iface.dpState.jumpMapFDs[ap.JumpMapFDMapKey()]
		}
		return false
	})
	return
}

func (m *bpfEndpointManager) setJumpMapFD(ap attachPoint, fd bpf.MapFD) {
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	m.withIface(ap.IfaceName(), func(iface *bpfInterface) bool {
		if fd > 0 {
			if iface.dpState.jumpMapFDs == nil {
				iface.dpState.jumpMapFDs = make(map[string]bpf.MapFD)
			}
			iface.dpState.jumpMapFDs[ap.JumpMapFDMapKey()] = fd
		} else if iface.dpState.jumpMapFDs != nil {
			delete(iface.dpState.jumpMapFDs, ap.JumpMapFDMapKey())
			if len(iface.dpState.jumpMapFDs) == 0 {
				iface.dpState.jumpMapFDs = nil
			}
		}
		ap.Log().Debugf("Jump map now %v fd=%v", iface.dpState.jumpMapFDs, fd)
		return false
	})
}

func (m *bpfEndpointManager) updatePolicyProgram(jumpMapFD bpf.MapFD, rules polprog.Rules) error {
	pg := polprog.NewBuilder(m.ipSetIDAlloc, m.bpfMapContext.IpsetsMap.MapFD(), m.bpfMapContext.StateMap.MapFD(), jumpMapFD)
	insns, err := pg.Instructions(rules)
	if err != nil {
		return fmt.Errorf("failed to generate policy bytecode: %w", err)
	}
	//progType := unix.BPF_PROG_TYPE_SCHED_CLS
	progType := 1
	if rules.ForXDP {
		// progType = unix.BPF_PROG_TYPE_XDP
		progType = 3
	}
	progFD, err := bpf.LoadBPFProgramFromInsns(insns, "Apache-2.0", uint32(progType))
	if err != nil {
		return fmt.Errorf("failed to load BPF policy program: %w", err)
	}
	defer func() {
		// Once we've put the program in the map, we don't need its FD any more.
		err := progFD.Close()
		if err != nil {
			log.WithError(err).Panic("Failed to close program FD.")
		}
	}()
	k := make([]byte, 4)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(progFD))
	err = bpf.UpdateMapEntry(jumpMapFD, k, v)
	if err != nil {
		return fmt.Errorf("failed to update %v=%v in jump map %v: %w", k, v, jumpMapFD, err)
	}
	return nil
}

func (m *bpfEndpointManager) removePolicyProgram(jumpMapFD bpf.MapFD) error {
	k := make([]byte, 4)
	err := bpf.DeleteMapEntryIfExists(jumpMapFD, k, 4)
	if err != nil {
		return fmt.Errorf("failed to update jump map: %w", err)
	}
	return nil
}

func FindJumpMap(progIDStr, ifaceName string) (mapFD bpf.MapFD, err error) {
	logCtx := log.WithField("progID", progIDStr).WithField("iface", ifaceName)
	logCtx.Debugf("Looking up jump map")
	bpftool := exec.Command("bpftool", "prog", "show", "id", progIDStr, "--json")
	output, err := bpftool.Output()
	if err != nil {
		// We can hit this case if the interface was deleted underneath us; check that it's still there.
		if _, err := os.Stat(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s", ifaceName)); os.IsNotExist(err) {
			// return 0, tc.ErrDeviceNotFound
			return 0, fmt.Errorf("song mock tc device not found")
		}
		return 0, fmt.Errorf("failed to get map metadata: %w out=\n%v", err, string(output))
	}
	var prog struct {
		MapIDs []int `json:"map_ids"`
	}
	err = json.Unmarshal(output, &prog)
	if err != nil {
		return 0, fmt.Errorf("failed to parse bpftool output: %w", err)
	}

	for _, mapID := range prog.MapIDs {
		mapFD, err := bpf.GetMapFDByID(mapID)
		if err != nil {
			return 0, fmt.Errorf("failed to get map FD from ID: %w", err)
		}
		mapInfo, err := bpf.GetMapInfo(mapFD)
		if err != nil {
			err = mapFD.Close()
			if err != nil {
				log.WithError(err).Panic("Failed to close FD.")
			}
			return 0, fmt.Errorf("failed to get map info: %w", err)
		}
		// if mapInfo.Type == unix.BPF_MAP_TYPE_PROG_ARRAY {
		if mapInfo.Type == 3 {
			logCtx.WithField("fd", mapFD).Debug("Found jump map")
			return mapFD, nil
		}
		err = mapFD.Close()
		if err != nil {
			log.WithError(err).Panic("Failed to close FD.")
		}
	}

	return 0, fmt.Errorf("failed to find jump map for iface=%v progID=%v", ifaceName, progIDStr)
}

func (m *bpfEndpointManager) getInterfaceIP(ifaceName string) (*net.IP, error) {
	var ipAddrs []net.IP
	if ip, ok := m.ifaceToIpMap[ifaceName]; ok {
		return &ip, nil
	}
	intf, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		switch t := addr.(type) {
		case *net.IPNet:
			if t.IP.To4() != nil {
				ipAddrs = append(ipAddrs, t.IP)
			}
		}
	}
	sort.Slice(ipAddrs, func(i, j int) bool {
		return bytes.Compare(ipAddrs[i], ipAddrs[j]) < 0
	})
	if len(ipAddrs) > 0 {
		return &ipAddrs[0], nil
	}
	return nil, errors.New("interface ip address not found")
}
