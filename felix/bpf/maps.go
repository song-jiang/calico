// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package bpf

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type IteratorAction string

const (
	IterNone   IteratorAction = ""
	IterDelete IteratorAction = "delete"
)

type IterCallback func(k, v []byte) IteratorAction

type Map interface {
	GetName() string
	// EnsureExists opens the map, creating and pinning it if needed.
	EnsureExists() error
	// Open opens the map, returns error if it does not exist.
	Open() error
	// MapFD gets the file descriptor of the map, only valid after calling EnsureExists().
	MapFD() MapFD
	// Path returns the path that the map is (to be) pinned to.
	Path() string

	// CopyDeltaFromOldMap() copies data from old map to new map
	CopyDeltaFromOldMap() error

	Iter(IterCallback) error
	Update(k, v []byte) error
	Get(k []byte) ([]byte, error)
	Delete(k []byte) error
}

type MapParameters struct {
	Filename     string
	Type         string
	KeySize      int
	ValueSize    int
	MaxEntries   int
	Name         string
	Flags        int
	Version      int
	UpdatedByBPF bool
}

func versionedStr(ver int, str string) string {
	if ver <= 1 {
		return str
	}

	return fmt.Sprintf("%s%d", str, ver)
}

func (mp *MapParameters) VersionedName() string {
	return versionedStr(mp.Version, mp.Name)
}

func (mp *MapParameters) versionedFilename() string {
	return versionedStr(mp.Version, mp.Filename)
}

type MapContext struct {
	RepinningEnabled bool
	IpsetsMap        Map
	StateMap         Map
	ArpMap           Map
	FailsafesMap     Map
	FrontendMap      Map
	BackendMap       Map
	AffinityMap      Map
	RouteMap         Map
	CtMap            Map
	SrMsgMap         Map
	CtNatsMap        Map
	MapSizes         map[string]uint32
}

func (c *MapContext) NewPinnedMap(params MapParameters) Map {
	// if len(params.VersionedName()) >= unix.BPF_OBJ_NAME_LEN {
	if len(params.VersionedName()) >= 16 {
		logrus.WithField("name", params.Name).Panic("Bug: BPF map name too long")
	}
	if val, ok := c.MapSizes[params.VersionedName()]; ok {
		params.MaxEntries = int(val)
	}

	m := &PinnedMap{
		context:       c,
		MapParameters: params,
		perCPU:        strings.Contains(params.Type, "percpu"),
	}
	return m
}

type PinnedMap struct {
	context *MapContext
	MapParameters

	fdLoaded bool
	fd       MapFD
	oldfd    MapFD
	perCPU   bool
	oldSize  int
}

func (b *PinnedMap) GetName() string {
	return b.VersionedName()
}

func (b *PinnedMap) MapFD() MapFD {
	if !b.fdLoaded {
		logrus.WithField("map", *b).Panic("MapFD() called without first calling EnsureExists()")
	}
	return b.fd
}

func (b *PinnedMap) Path() string {
	return b.versionedFilename()
}

func (b *PinnedMap) Close() error {
	err := b.fd.Close()
	b.fdLoaded = false
	b.oldfd = 0
	b.fd = 0
	return err
}

func (b *PinnedMap) RepinningEnabled() bool {
	if b.context == nil {
		return false
	}
	return b.context.RepinningEnabled
}

// Iter iterates over the map, passing each key/value pair to the provided callback function.  Warning:
// The key and value are owned by the iterator and will be clobbered by the next iteration so they must not be
// retained or modified.
func (b *PinnedMap) Iter(f IterCallback) error {
	it, err := NewMapIterator(b.MapFD(), b.KeySize, b.ValueSize, b.MaxEntries)
	if err != nil {
		return fmt.Errorf("failed to create BPF map iterator: %w", err)
	}
	defer func() {
		err := it.Close()
		if err != nil {
			logrus.WithError(err).Panic("Unexpected error from map iterator Close().")
		}
	}()

	keyToDelete := make([]byte, b.KeySize)
	var action IteratorAction
	for {
		k, v, err := it.Next()

		if action == IterDelete {
			// The previous iteration asked us to delete its key; do that now before we check for the end of
			// the iteration.
			err := DeleteMapEntry(b.MapFD(), keyToDelete, b.ValueSize)
			if err != nil && !IsNotExists(err) {
				return fmt.Errorf("failed to delete map entry: %w", err)
			}
		}

		if err != nil {
			if err == ErrIterationFinished {
				return nil
			}
			return errors.Errorf("iterating the map failed: %s", err)
		}

		action = f(k, v)

		if action == IterDelete {
			// k will become invalid once we call Next again so take a copy.
			copy(keyToDelete, k)
		}
	}
}

func (b *PinnedMap) Update(k, v []byte) error {
	if b.perCPU {
		// Per-CPU maps need a buffer of value-size * num-CPUs.
		logrus.Panic("Per-CPU operations not implemented")
	}
	return UpdateMapEntry(b.fd, k, v)
}

func (b *PinnedMap) Get(k []byte) ([]byte, error) {
	if b.perCPU {
		// Per-CPU maps need a buffer of value-size * num-CPUs.
		logrus.Panic("Per-CPU operations not implemented")
	}
	return GetMapEntry(b.fd, k, b.ValueSize)
}

func (b *PinnedMap) Delete(k []byte) error {
	if b.perCPU {
		logrus.Panic("Per-CPU operations not implemented")
	}
	return DeleteMapEntry(b.fd, k, b.ValueSize)
}

func (b *PinnedMap) updateDeltaEntries() error {
	numEntriesCopied := 0
	mapMem := make(map[string]struct{})
	it, err := NewMapIterator(b.oldfd, b.KeySize, b.ValueSize, b.oldSize)
	if err != nil {
		return fmt.Errorf("failed to create BPF map iterator: %w", err)
	}
	defer func() {
		err := it.Close()
		if err != nil {
			logrus.WithError(err).Panic("Unexpected error from map iterator Close().")
		}
	}()
	for {
		k, v, err := it.Next()

		if err != nil {
			if err == ErrIterationFinished {
				return nil
			}
			return errors.Errorf("iterating the old map failed: %s", err)
		}
		if numEntriesCopied == b.MaxEntries {
			return fmt.Errorf("new map cannot hold all the data from the old map %s.", b.GetName())
		}

		if _, ok := mapMem[string(k)]; ok {
			continue
		}
		newValue, err := b.Get(k)
		if err == nil && reflect.DeepEqual(newValue, v) {
			numEntriesCopied++
			continue
		}
		err = b.Update(k, v)
		if err != nil {
			return fmt.Errorf("error copying data from the old map")
		}
		logrus.Debugf("copied data from old map to new map key=%v, value=%v", k, v)
		mapMem[string(k)] = struct{}{}
		numEntriesCopied++
	}
}

func (b *PinnedMap) copyFromOldMap() error {
	numEntriesCopied := 0
	mapMem := make(map[string]struct{})
	it, err := NewMapIterator(b.oldfd, b.KeySize, b.ValueSize, b.oldSize)
	if err != nil {
		return fmt.Errorf("failed to create BPF map iterator: %w", err)
	}
	defer func() {
		err := it.Close()
		if err != nil {
			logrus.WithError(err).Panic("Unexpected error from map iterator Close().")
		}
	}()

	for {
		k, v, err := it.Next()

		if err != nil {
			if err == ErrIterationFinished {
				return nil
			}
			return errors.Errorf("iterating the old map failed: %s", err)
		}

		if numEntriesCopied == b.MaxEntries {
			return fmt.Errorf("new map cannot hold all the data from the old map %s", b.GetName())
		}
		if _, ok := mapMem[string(k)]; ok {
			continue
		}

		err = b.Update(k, v)
		if err != nil {
			return fmt.Errorf("error copying data from the old map")
		}
		logrus.Debugf("copied data from old map to new map key=%v, value=%v", k, v)
		mapMem[string(k)] = struct{}{}
		numEntriesCopied++
	}
}

func (b *PinnedMap) repinAt(from, to string) error {
	err := RepinMap(b.VersionedName(), to)
	if err != nil {
		return fmt.Errorf("error repinning %s to %s: %w", from, to, err)
	}
	err = os.Remove(from)
	if err != nil {
		return fmt.Errorf("error removing the pin %s", from)
	}
	return nil
}

type bpftoolMapMeta struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func (b *PinnedMap) CopyDeltaFromOldMap() error {
	if b.oldfd == 0 {
		return nil
	}

	defer func() {
		b.oldfd.Close()
		b.oldfd = 0
		os.Remove(b.Path() + "_old")
	}()

	err := b.updateDeltaEntries()
	if err != nil {
		return fmt.Errorf("error copying data from old map %s, err=%w", b.GetName(), err)
	}
	return nil
}
