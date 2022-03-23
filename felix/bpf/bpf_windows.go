// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

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

// Package bpf provides primitives to manage Calico-specific XDP programs
// attached to network interfaces, along with the blacklist LPM map and the
// failsafe map.
//
// It does not call the bpf() syscall itself but executes external programs
// like bpftool and ip.
package bpf

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/labelindex"
)

type XDPMode int

const (
	XDPDriver XDPMode = iota
	XDPOffload
	XDPGeneric
)

type FindObjectMode uint32

const (
	FindInBPFFSOnly FindObjectMode = 1 << iota
	FindByID
)

const (
	// XDP
	cidrMapVersion        = "v1"
	failsafeMapVersion    = "v1"
	xdpProgVersion        = "v1"
	failsafeMapName       = "calico_failsafe_ports_" + failsafeMapVersion
	failsafeSymbolMapName = "calico_failsafe_ports" // no need to version the symbol name
)

var (
	xdpFilename     = "filter.o"
	sockopsFilename = "sockops.o"
	redirFilename   = "redir.o"

	bpfCalicoSubdir = "calico"
	ifaceRegexp     = regexp.MustCompile(`(?m)^[0-9]+:\s+(?P<name>.+):`)
)

func (m XDPMode) String() string {
	switch m {
	case XDPDriver:
		return "xdpdrv"
	case XDPOffload:
		return "xdpoffload"
	case XDPGeneric:
		return "xdpgeneric"
	default:
		return "unknown"
	}
}

// XXX maybe use ipsets.IPFamily
type IPFamily int

const (
	IPFamilyUnknown IPFamily = iota
	IPFamilyV4
	IPFamilyV6
)

func (m IPFamily) String() string {
	switch m {
	case IPFamilyV4:
		return "ipv4"
	case IPFamilyV6:
		return "ipv6"
	default:
		return "unknown"
	}
}

func (m IPFamily) Size() int {
	switch m {
	case IPFamilyV4:
		return 4
	case IPFamilyV6:
		return 16
	}
	return -1
}

func printCommand(name string, arg ...string) {
	log.Debugf("running: %s %s", name, strings.Join(arg, " "))
}

type BPFLib struct {
	binDir      string
	bpffsDir    string
	calicoDir   string
	sockmapDir  string
	cgroupV2Dir string
	xdpDir      string
}

type BPFDataplane interface {
	DumpCIDRMap(ifName string, family IPFamily) (map[CIDRMapKey]uint32, error)
	DumpFailsafeMap() ([]ProtoPort, error)
	GetCIDRMapID(ifName string, family IPFamily) (int, error)
	GetFailsafeMapID() (int, error)
	GetMapsFromXDP(ifName string) ([]int, error)
	GetXDPID(ifName string) (int, error)
	GetXDPMode(ifName string) (XDPMode, error)
	GetXDPIfaces() ([]string, error)
	GetXDPObjTag(objPath string) (string, error)
	GetXDPObjTagAuto() (string, error)
	GetXDPTag(ifName string) (string, error)
	IsValidMap(ifName string, family IPFamily) (bool, error)
	ListCIDRMaps(family IPFamily) ([]string, error)
	LoadXDP(objPath, ifName string, mode XDPMode) error
	LoadXDPAuto(ifName string, mode XDPMode) error
	LookupCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) (uint32, error)
	LookupFailsafeMap(proto uint8, port uint16) (bool, error)
	NewCIDRMap(ifName string, family IPFamily) (string, error)
	NewFailsafeMap() (string, error)
	RemoveCIDRMap(ifName string, family IPFamily) error
	RemoveFailsafeMap() error
	RemoveItemCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) error
	RemoveItemFailsafeMap(proto uint8, port uint16) error
	RemoveXDP(ifName string, mode XDPMode) error
	UpdateCIDRMap(ifName string, family IPFamily, ip net.IP, mask int, refCount uint32) error
	UpdateFailsafeMap(proto uint8, port uint16) error
	loadXDPRaw(objPath, ifName string, mode XDPMode, mapArgs []string) error
	GetBPFCalicoDir() string
	AttachToSockmap() error
	DetachFromSockmap(mode FindObjectMode) error
	RemoveSockmap(mode FindObjectMode) error
	loadBPF(objPath, progPath, progType string, mapArgs []string) error
	LoadSockops(objPath string) error
	LoadSockopsAuto() error
	RemoveSockops() error
	LoadSkMsg(objPath string) error
	LoadSkMsgAuto() error
	RemoveSkMsg() error
	AttachToCgroup() error
	DetachFromCgroup(mode FindObjectMode) error
	NewSockmapEndpointsMap() (string, error)
	NewSockmap() (string, error)
	UpdateSockmapEndpoints(ip net.IP, mask int) error
	DumpSockmapEndpointsMap(family IPFamily) ([]CIDRMapKey, error)
	LookupSockmapEndpointsMap(ip net.IP, mask int) (bool, error)
	RemoveItemSockmapEndpointsMap(ip net.IP, mask int) error
	RemoveSockmapEndpointsMap() error
}

func getCIDRMapName(ifName string, family IPFamily) string {
	return fmt.Sprintf("%s_%s_%s_blacklist", ifName, family, cidrMapVersion)
}

func getProgName(ifName string) string {
	return fmt.Sprintf("prefilter_%s_%s", xdpProgVersion, ifName)
}

func newMap(name, path, kind string, entries, keySize, valueSize, flags int) (string, error) {
	// FIXME: for some reason this function was called several times for a
	// particular map, just assume it's created if the pinned file is there for
	// now
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}

	prog := "bpftool"
	args := []string{
		"map",
		"create",
		path,
		"type",
		kind,
		"key",
		fmt.Sprintf("%d", keySize),
		"value",
		fmt.Sprintf("%d", valueSize),
		"entries",
		fmt.Sprintf("%d", entries),
		"name",
		name,
		"flags",
		fmt.Sprintf("%d", flags),
	}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to create map (%s): %s\n%s", name, err, output)
	}

	return path, nil
}

func (b *BPFLib) NewFailsafeMap() (string, error) {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	keySize := 4
	valueSize := 1

	return newMap(mapName,
		mapPath,
		"hash",
		65535,
		keySize,
		valueSize,
		1, // BPF_F_NO_PREALLOC
	)
}

func (b *BPFLib) GetBPFCalicoDir() string {
	return b.calicoDir
}

func (b *BPFLib) NewCIDRMap(ifName string, family IPFamily) (string, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if family == IPFamilyV6 {
		return "", errors.New("IPv6 not supported")
	}

	keySize := 8
	valueSize := 4

	return newMap(mapName,
		mapPath,
		"lpm_trie",
		10240,
		keySize,
		valueSize,
		1, // BPF_F_NO_PREALLOC
	)
}

func (b *BPFLib) ListCIDRMaps(family IPFamily) ([]string, error) {
	var ifNames []string
	maps, err := ioutil.ReadDir(b.xdpDir)
	if err != nil {
		return nil, err
	}

	suffix := fmt.Sprintf("_%s_%s_blacklist", family, cidrMapVersion)
	for _, m := range maps {
		name := m.Name()
		if strings.HasSuffix(name, suffix) {
			ifName := strings.TrimSuffix(name, suffix)
			ifNames = append(ifNames, ifName)
		}
	}

	return ifNames, nil
}

func (b *BPFLib) RemoveFailsafeMap() error {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	return os.Remove(mapPath)
}

func (b *BPFLib) RemoveCIDRMap(ifName string, family IPFamily) error {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	return os.Remove(mapPath)
}

type mapInfo struct {
	Id        int    `json:"id"`
	Type      string `json:"type"`
	KeySize   int    `json:"bytes_key"`
	ValueSize int    `json:"bytes_value"`
	Err       string `json:"error"`
}

type getnextEntry struct {
	Key     []string `json:"key"`
	NextKey []string `json:"next_key"`
	Err     string   `json:"error"`
}

type mapEntry struct {
	Key   []string `json:"key"`
	Value []string `json:"value"`
	Err   string   `json:"error"`
}

type progInfo struct {
	Id     int    `json:"id"`
	Type   string `json:"type"`
	Tag    string `json:"tag"`
	MapIds []int  `json:"map_ids"`
	Err    string `json:"error"`
}

type cgroupProgEntry struct {
	ID          int    `json:"id"`
	AttachType  string `json:"attach_type"`
	AttachFlags string `json:"attach_flags"`
	Name        string `json:"name"`
	Err         string `json:"error"`
}

type ProtoPort struct {
	Proto labelindex.IPSetPortProtocol
	Port  uint16
}

func getMapStructGeneral(mapDesc []string) (*mapInfo, error) {
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"show"}
	args = append(args, mapDesc...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to show map (%v): %s\n%s", mapDesc, err, output)
	}

	m := mapInfo{}
	err = json.Unmarshal(output, &m)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if m.Err != "" {
		return nil, fmt.Errorf("%s", m.Err)
	}
	return &m, nil
}

func getMapStruct(mapPath string) (*mapInfo, error) {
	return getMapStructGeneral([]string{"pinned", mapPath})
}

func (b *BPFLib) GetFailsafeMapID() (int, error) {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	m, err := getMapStruct(mapPath)
	if err != nil {
		return -1, err
	}
	return m.Id, nil
}

func (b *BPFLib) DumpFailsafeMap() ([]ProtoPort, error) {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"dump",
		"pinned",
		mapPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to dump map (%s): %s\n%s", mapPath, err, output)
	}

	l := []mapEntry{}
	err = json.Unmarshal(output, &l)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	pp := []ProtoPort{}
	for _, entry := range l {
		proto, port, err := hexToFailsafe(entry.Key)
		if err != nil {
			return nil, err
		}
		pp = append(pp, ProtoPort{labelindex.IPSetPortProtocol(proto), port})
	}

	return pp, nil
}

func (b *BPFLib) GetCIDRMapID(ifName string, family IPFamily) (int, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	m, err := getMapStruct(mapPath)
	if err != nil {
		return -1, err
	}
	return m.Id, nil
}

func (b *BPFLib) IsValidMap(ifName string, family IPFamily) (bool, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	m, err := getMapStruct(mapPath)
	if err != nil {
		return false, err
	}
	switch family {
	case IPFamilyV4:
		if m.Type != "lpm_trie" || m.KeySize != 8 || m.ValueSize != 4 {
			return false, nil
		}
	case IPFamilyV6:
		return false, fmt.Errorf("IPv6 not implemented yet")
	default:
		return false, fmt.Errorf("unknown IP family %d", family)
	}
	return true, nil
}

func (b *BPFLib) LookupFailsafeMap(proto uint8, port uint16) (bool, error) {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return false, err
	}

	hexKey, err := failsafeToHex(proto, port)
	if err != nil {
		return false, err
	}

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"lookup",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to lookup in map (%s): %s\n%s", mapName, err, output)
	}

	l := mapEntry{}
	err = json.Unmarshal(output, &l)
	if err != nil {
		return false, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if l.Err != "" {
		return false, fmt.Errorf("%s", l.Err)
	}

	return true, err
}

func (b *BPFLib) LookupCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) (uint32, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return 0, err
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), mask)

	hexKey, err := CidrToHex(cidr)
	if err != nil {
		return 0, err
	}

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"lookup",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("failed to lookup in map (%s): %s\n%s", mapName, err, output)
	}

	l := mapEntry{}
	err = json.Unmarshal(output, &l)
	if err != nil {
		return 0, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if l.Err != "" {
		return 0, fmt.Errorf("%s", l.Err)
	}

	val, err := hexToCIDRMapValue(l.Value)
	if err != nil {
		return 0, err
	}

	return val, err
}

type CIDRMapKey struct {
	rawIP   [16]byte
	rawMask [16]byte
}

func (k *CIDRMapKey) ToIPNet() *net.IPNet {
	ip := net.IP(k.rawIP[:]).To16()
	mask := func() net.IPMask {
		if ip.To4() != nil {
			// it's an IPV4 address
			return k.rawMask[12:16]
		} else {
			return k.rawMask[:]
		}
	}()
	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
}

func NewCIDRMapKey(n *net.IPNet) CIDRMapKey {
	k := CIDRMapKey{
		rawMask: [16]byte{
			0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff,
		},
	}
	rawIPSlice := k.rawIP[:]
	copy(rawIPSlice, n.IP.To16())
	rawMaskSlice := k.rawMask[len(k.rawMask)-len(n.Mask):]
	copy(rawMaskSlice, n.Mask)
	return k
}

func (b *BPFLib) DumpCIDRMap(ifName string, family IPFamily) (map[CIDRMapKey]uint32, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return nil, err
	}

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"dump",
		"pinned",
		mapPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to dump in map (%s): %s\n%s", mapName, err, output)
	}

	var al []mapEntry
	err = json.Unmarshal(output, &al)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	m := make(map[CIDRMapKey]uint32, len(al))
	for _, l := range al {
		ipnet, err := hexToIPNet(l.Key, family)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bpf map key (%v) to ip and mask: %v", l.Key, err)
		}
		value, err := hexToCIDRMapValue(l.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bpf map value (%v): %v", l.Value, err)
		}
		m[NewCIDRMapKey(ipnet)] = value
	}

	return m, nil
}

func (b *BPFLib) RemoveItemFailsafeMap(proto uint8, port uint16) error {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return err
	}

	hexKey, err := failsafeToHex(proto, port)
	if err != nil {
		return err
	}

	prog := "bpftool"
	args := []string{
		"map",
		"delete",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete item (%d) from map (%s): %s\n%s", port, mapName, err, output)
	}

	return nil
}

func (b *BPFLib) RemoveItemCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) error {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return err
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), mask)

	hexKey, err := CidrToHex(cidr)
	if err != nil {
		return err
	}

	prog := "bpftool"
	args := []string{
		"map",
		"delete",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete item (%v/%d) from map (%s): %s\n%s", ip, mask, mapName, err, output)
	}

	return nil
}

func (b *BPFLib) UpdateFailsafeMap(proto uint8, port uint16) error {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return err
	}

	hexKey, err := failsafeToHex(proto, port)
	if err != nil {
		return err
	}

	prog := "bpftool"
	args := []string{
		"map",
		"update",
		"pinned",
		mapPath,
		"key",
		"hex"}
	args = append(args, hexKey...)
	args = append(args, []string{
		"value",
		fmt.Sprintf("%d", 1), // it's just a set, so use 1 as value
	}...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update map (%s) with (%d): %s\n%s", mapName, port, err, output)
	}

	return nil
}

func (b *BPFLib) UpdateCIDRMap(ifName string, family IPFamily, ip net.IP, mask int, refCount uint32) error {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return err
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), mask)

	hexKey, err := CidrToHex(cidr)
	if err != nil {
		return err
	}
	hexValue := cidrMapValueToHex(refCount)

	prog := "bpftool"
	args := []string{
		"map",
		"update",
		"pinned",
		mapPath,
		"key",
		"hex"}
	args = append(args, hexKey...)
	args = append(args, "value", "hex")
	args = append(args, hexValue...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update map (%s) with (%v/%d): %s\n%s", mapName, ip, mask, err, output)
	}

	return nil
}

func (b *BPFLib) loadXDPRaw(objPath, ifName string, mode XDPMode, mapArgs []string) error {
	objPath = path.Join(b.binDir, objPath)

	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		return fmt.Errorf("cannot find XDP object %q", objPath)
	}

	progName := getProgName(ifName)
	progPath := filepath.Join(b.xdpDir, progName)

	if err := b.loadBPF(objPath, progPath, "xdp", mapArgs); err != nil {
		return err
	}

	prog := "ip"
	args := []string{
		"link",
		"set",
		"dev",
		ifName,
		mode.String(),
		"pinned",
		progPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	log.Debugf("out:\n%v", string(output))

	if err != nil {
		if removeErr := os.Remove(progPath); removeErr != nil {
			return fmt.Errorf("failed to attach XDP program (%s) to %s: %s (also failed to remove the pinned program: %s)\n%s", progPath, ifName, err, removeErr, output)
		} else {
			return fmt.Errorf("failed to attach XDP program (%s) to %s: %s\n%s", progPath, ifName, err, output)
		}
	}

	return nil
}

func (b *BPFLib) getMapArgs(ifName string) ([]string, error) {
	// FIXME harcoded ipv4, do we need both?
	mapName := getCIDRMapName(ifName, IPFamilyV4)
	mapPath := filepath.Join(b.xdpDir, mapName)

	failsafeMapPath := filepath.Join(b.calicoDir, failsafeMapName)

	// key: symbol of the map definition in the XDP program
	// value: path where the map is pinned
	maps := map[string]string{
		"calico_prefilter_v4": mapPath,
		failsafeSymbolMapName: failsafeMapPath,
	}

	var mapArgs []string

	for n, p := range maps {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return nil, fmt.Errorf("map %q needs to be loaded first", p)
		}

		mapArgs = append(mapArgs, []string{"map", "name", n, "pinned", p}...)
	}

	return mapArgs, nil
}

func (b *BPFLib) LoadXDP(objPath, ifName string, mode XDPMode) error {
	mapArgs, err := b.getMapArgs(ifName)
	if err != nil {
		return err
	}

	return b.loadXDPRaw(objPath, ifName, mode, mapArgs)
}

func (b *BPFLib) LoadXDPAuto(ifName string, mode XDPMode) error {
	return b.LoadXDP(xdpFilename, ifName, mode)
}

func (b *BPFLib) RemoveXDP(ifName string, mode XDPMode) error {
	progName := getProgName(ifName)
	progPath := filepath.Join(b.xdpDir, progName)

	prog := "ip"
	args := []string{
		"link",
		"set",
		"dev",
		ifName,
		mode.String(),
		"off"}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to detach XDP program (%s) from %s: %s\n%s", progPath, ifName, err, output)
	}

	return os.Remove(progPath)
}

func (b *BPFLib) GetXDPTag(ifName string) (string, error) {
	progName := getProgName(ifName)
	progPath := filepath.Join(b.xdpDir, progName)

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"prog",
		"show",
		"pinned",
		progPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to show XDP program (%s): %s\n%s", progPath, err, output)
	}

	p := progInfo{}
	err = json.Unmarshal(output, &p)
	if err != nil {
		return "", fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if p.Err != "" {
		return "", fmt.Errorf("%s", p.Err)
	}

	return p.Tag, nil
}

func (b *BPFLib) GetMapsFromXDP(ifName string) ([]int, error) {
	progName := getProgName(ifName)
	progPath := filepath.Join(b.xdpDir, progName)

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"prog",
		"show",
		"pinned",
		progPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to show XDP program (%s): %s\n%s", progPath, err, output)
	}
	p := progInfo{}
	err = json.Unmarshal(output, &p)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if p.Err != "" {
		return nil, fmt.Errorf("%s", p.Err)
	}

	return p.MapIds, nil
}

func (b *BPFLib) GetXDPID(ifName string) (int, error) {
	prog := "ip"
	args := []string{
		"link",
		"show",
		"dev",
		ifName}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("failed to show interface information (%s): %s\n%s", ifName, err, output)
	}

	s := strings.Fields(string(output))
	for i := range s {
		// Example of output:
		//
		// 196: test_A@test_B: <BROADCAST,MULTICAST> mtu 1500 xdpgeneric qdisc noop state DOWN mode DEFAULT group default qlen 1000
		//    link/ether 1a:d0:df:a5:12:59 brd ff:ff:ff:ff:ff:ff
		//    prog/xdp id 175 tag 5199fa060702bbff jited
		if s[i] == "prog/xdp" && len(s) > i+2 && s[i+1] == "id" {
			id, err := strconv.Atoi(s[i+2])
			if err != nil {
				continue
			}
			return id, nil
		}
	}

	return -1, errors.New("ID not found")
}

func (b *BPFLib) GetXDPMode(ifName string) (XDPMode, error) {
	prog := "ip"
	args := []string{
		"link",
		"show",
		"dev",
		ifName}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return XDPGeneric, fmt.Errorf("failed to show interface information (%s): %s\n%s", ifName, err, output)
	}

	s := strings.Fields(string(output))
	// Note: using a slice (rather than a map[string]XDPMode) here to ensure deterministic ordering.
	for _, modeMapping := range []struct {
		String string
		Mode   XDPMode
	}{
		{"xdpgeneric", XDPGeneric},
		{"xdpoffload", XDPOffload},
		{"xdp", XDPDriver}, // We write "xdpdrv" but read back "xdp"
	} {
		for _, f := range s {
			if f == modeMapping.String {
				return modeMapping.Mode, nil
			}
		}
	}

	return XDPGeneric, errors.New("ID not found")
}

func (b *BPFLib) GetXDPIfaces() ([]string, error) {
	var xdpIfaces []string

	prog := "ip"
	args := []string{
		"link",
		"show"}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to show interface informations: %s\n%s", err, output)
	}

	m := ifaceRegexp.FindAllStringSubmatch(string(output), -1)
	if len(m) < 2 {
		return nil, fmt.Errorf("failed to parse interface informations")
	}

	for _, i := range m {
		if len(i) != 2 {
			continue
		}

		// handle paired interfaces
		ifaceParts := strings.Split(i[1], "@")
		ifaceName := ifaceParts[0]

		if _, err := b.GetXDPID(ifaceName); err == nil {
			xdpIfaces = append(xdpIfaces, ifaceName)
		}
	}

	return xdpIfaces, nil
}

// failsafeToHex takes a protocol and port number and outputs a string slice
// of hex-encoded bytes ready to be passed to bpftool.
//
// For example, for 8080/TCP:
//
// [
//  06,     IPPROTO_TCP as defined by <linux/in.h>
//  00,     padding
//  90, 1F  LSB in little endian order
// ]
func failsafeToHex(proto uint8, port uint16) ([]string, error) {
	portBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBytes, port)

	hexStr := fmt.Sprintf("%02x 00 %02x %02x",
		proto,
		portBytes[0], portBytes[1])

	return strings.Split(hexStr, " "), nil
}

func hexToByte(hexString string) (byte, error) {
	hex := strings.TrimPrefix(hexString, "0x")
	proto64, err := strconv.ParseUint(hex, 16, 8)
	if err != nil {
		return 0, err
	}
	return byte(proto64), nil
}

// hexToFailsafe takes the bpftool hex representation of a protocol and port
// number and returns the protocol and port number.
func hexToFailsafe(hexString []string) (proto uint8, port uint16, err error) {
	proto, err = hexToByte(hexString[0])
	if err != nil {
		return
	}

	padding, err := hexToByte(hexString[1])
	if err != nil {
		return
	}

	if padding != 0 {
		err = fmt.Errorf("invalid proto in hex string: %q\n", hexString[1])
		return
	}

	portMSB, err := hexToByte(hexString[2])
	if err != nil {
		err = fmt.Errorf("invalid port MSB in hex string: %q\n", hexString[2])
		return
	}

	portLSB, err := hexToByte(hexString[3])
	if err != nil {
		err = fmt.Errorf("invalid port LSB in hex string: %q\n", hexString[3])
		return
	}

	port = binary.LittleEndian.Uint16([]byte{portLSB, portMSB})
	return
}

// CidrToHex takes a CIDR in string form (e.g. "192.168.0.0/16") and outputs a
// string slice of hex-encoded bytes ready to be passed to bpftool.
//
// For example, for "192.168.0.0/16":
//
// [
//  10, 00, 00, 00,   mask in little endian order
//  C0, A8, 00, 00    IP address
// ]
func CidrToHex(cidr string) ([]string, error) {
	cidrParts := strings.Split(cidr, "/")
	if len(cidrParts) != 2 {
		return nil, fmt.Errorf("failed to split CIDR %q", cidr)
	}
	rawIP := cidrParts[0]

	mask, err := strconv.Atoi(cidrParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to convert mask %d to int", mask)
	}

	ip := net.ParseIP(rawIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", rawIP)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("IP %q is not IPv4", ip)
	}

	maskBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(maskBytes, uint32(mask))

	hexStr := fmt.Sprintf("%02x %02x %02x %02x %02x %02x %02x %02x",
		maskBytes[0], maskBytes[1], maskBytes[2], maskBytes[3],
		ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	return strings.Split(hexStr, " "), nil
}

// hexToIPNet takes the bpftool hex representation of a CIDR (see above) and
// returns a net.IPNet.
func hexToIPNet(hexStrings []string, family IPFamily) (*net.IPNet, error) {
	hex, err := hexStringsToBytes(hexStrings)
	if err != nil {
		return nil, err
	}
	maskBytes := hex[0:4]
	ipBytes := hex[4:]
	mask := int(binary.LittleEndian.Uint32(maskBytes))

	return &net.IPNet{
		IP:   ipBytes,
		Mask: net.CIDRMask(mask, family.Size()*8),
	}, nil
}

// hexToCIDRMapValue takes a string slice containing the bpftool hex
// representation of a 1-byte value and returns it as an uint32
func hexToCIDRMapValue(hexStrings []string) (uint32, error) {
	hex, err := hexStringsToBytes(hexStrings)
	if err != nil {
		return 0, err
	}
	if len(hex) != 4 {
		return 0, fmt.Errorf("wrong size of hex in %q", hexStrings)
	}
	return nativeEndian.Uint32(hex), nil
}

// cidrMapValueToHex takes a ref count as unsigned 32 bit number and
// turns it into an array of hex strings, which bpftool can understand.
func cidrMapValueToHex(refCount uint32) []string {
	refCountBytes := make([]byte, 4)
	nativeEndian.PutUint32(refCountBytes, refCount)

	hexStr := fmt.Sprintf("%02x %02x %02x %02x",
		refCountBytes[0], refCountBytes[1], refCountBytes[2], refCountBytes[3])

	return strings.Split(hexStr, " ")
}

// hexStringsToBytes takes a string slice containing bpf data represented as
// bpftool hex and returns a slice of bytes containing that data.
func hexStringsToBytes(hexStrings []string) ([]byte, error) {
	var hex []byte
	for _, b := range hexStrings {
		h, err := hexToByte(b)
		if err != nil {
			return nil, err
		}
		hex = append(hex, byte(h))
	}
	return hex, nil
}

func MemberToIPMask(member string) (*net.IP, int, error) {
	var (
		mask  int
		rawIP string
	)

	memberParts := strings.Split(member, "/")
	switch len(memberParts) {
	case 1:
		mask = 32
		rawIP = memberParts[0]
	case 2:
		var err error
		mask, err = strconv.Atoi(memberParts[1])
		if err != nil {
			return nil, -1, fmt.Errorf("failed to convert mask %d to int", mask)
		}
		rawIP = memberParts[0]
	default:
		return nil, -1, fmt.Errorf("invalid member format %q", member)
	}

	ip := net.ParseIP(rawIP)
	if ip == nil {
		return nil, -1, fmt.Errorf("invalid IP %q", rawIP)
	}

	return &ip, mask, nil
}

func SupportsXDP() error {
	// Test endianness
	if nativeEndian != binary.LittleEndian {
		return fmt.Errorf("this bpf library only supports little endian architectures")
	}

	return nil
}

func getAllProgs() ([]progInfo, error) {
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"prog",
		"show",
	}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get progs: %s\n%s", err, output)
	}

	var progs []progInfo
	err = json.Unmarshal(output, &progs)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	return progs, nil
}

func (b *BPFLib) getAllMaps() ([]mapInfo, error) {
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"show"}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get all maps: %s\n%s", err, output)
	}

	var maps []mapInfo
	err = json.Unmarshal(output, &maps)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	return maps, nil
}

func (b *BPFLib) loadBPF(objPath, progPath, progType string, mapArgs []string) error {
	if err := os.MkdirAll(filepath.Dir(progPath), 0700); err != nil {
		return err
	}

	prog := "bpftool"
	args := []string{
		"prog",
		"load",
		objPath,
		progPath,
		"type",
		progType}

	args = append(args, mapArgs...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	log.Debugf("out:\n%v", string(output))

	if err != nil {
		// FIXME: for some reason this function was called several times for a
		// particular XDP program, just assume the map is loaded if the pinned
		// file is there for now
		if _, err := os.Stat(progPath); err != nil {
			return fmt.Errorf("failed to load BPF program (%s): %s\n%s", objPath, err, output)
		}
	}

	return nil
}

func SupportsBPFDataplane() error {
	// Test endianness
	if nativeEndian != binary.LittleEndian {
		return errors.New("this bpf library only supports little endian architectures")
	}

	if !SyscallSupport() {
		return errors.New("BPF syscall support is not available on this platform")
	}

	return nil
}

// KTimeNanos returns a nanosecond timestamp that is comparable with the ones generated by BPF.
func KTimeNanos() int64 {
	// TODO
	return 0
}
