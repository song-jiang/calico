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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func ShowMapCmd(m Map) ([]string, error) {
	if pm, ok := m.(*PinnedMap); ok {
		return []string{
			"bpftool",
			"--json",
			"--pretty",
			"map",
			"show",
			"pinned",
			pm.versionedFilename(),
		}, nil
	}

	return nil, errors.Errorf("unrecognized map type %T", m)
}

// DumpMapCmd returns the command that can be used to dump a map or an error
func DumpMapCmd(m Map) ([]string, error) {
	if pm, ok := m.(*PinnedMap); ok {
		return []string{
			"bpftool",
			"--json",
			"--pretty",
			"map",
			"dump",
			"pinned",
			pm.versionedFilename(),
		}, nil
	}

	return nil, errors.Errorf("unrecognized map type %T", m)
}

func MapDeleteKeyCmd(m Map, key []byte) ([]string, error) {
	if pm, ok := m.(*PinnedMap); ok {
		keyData := make([]string, len(key))
		for i, b := range key {
			keyData[i] = fmt.Sprintf("%d", b)
		}
		cmd := []string{
			"bpftool",
			"--json",
			"--pretty",
			"map",
			"delete",
			"pinned",
			pm.versionedFilename(),
			"key",
		}

		cmd = append(cmd, keyData...)

		return cmd, nil
	}

	return nil, errors.Errorf("unrecognized map type %T", m)
}

// IterMapCmdOutput iterates over the outout of a command obtained by DumpMapCmd
func IterMapCmdOutput(output []byte, f IterCallback) error {
	var mp []mapEntry
	err := json.Unmarshal(output, &mp)
	if err != nil {
		return errors.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	for _, me := range mp {
		k, err := hexStringsToBytes(me.Key)
		if err != nil {
			return errors.Errorf("failed parsing entry %s key: %e", me, err)
		}
		v, err := hexStringsToBytes(me.Value)
		if err != nil {
			return errors.Errorf("failed parsing entry %s val: %e", me, err)
		}
		f(k, v)
	}

	return nil
}

func (b *PinnedMap) Open() error {
	if b.fdLoaded {
		return nil
	}

	_, err := MaybeMountBPFfs()
	if err != nil {
		logrus.WithError(err).Error("Failed to mount bpffs")
		return err
	}
	// FIXME hard-coded dir
	err = os.MkdirAll("/sys/fs/bpf/tc/globals", 0700)
	if err != nil {
		logrus.WithError(err).Error("Failed create dir")
		return err
	}

	_, err = os.Stat(b.versionedFilename())
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		logrus.Debug("Map file didn't exist")
		if b.context.RepinningEnabled {
			logrus.WithField("name", b.Name).Info("Looking for map by name (to repin it)")
			err = RepinMap(b.VersionedName(), b.versionedFilename())
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}

	if err == nil {
		logrus.Debug("Map file already exists, trying to open it")
		b.fd, err = GetMapFDByPin(b.versionedFilename())
		if err == nil {
			b.fdLoaded = true
			logrus.WithField("fd", b.fd).WithField("name", b.versionedFilename()).
				Info("Loaded map file descriptor.")
			return nil
		}
		return err
	}

	return err
}

func (b *PinnedMap) oldMapExists() bool {
	_, err := os.Stat(b.Path() + "_old")
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func (b *PinnedMap) EnsureExists() error {
	oldMapPath := b.Path() + "_old"
	copyData := false
	if b.fdLoaded {
		return nil
	}

	// In case felix restarts in the middle of migration, we might end up with
	// old map. Repin the old map and let the map creation continue.
	if b.oldMapExists() {
		if _, err := os.Stat(b.Path()); err == nil {
			os.Remove(b.Path())
		}
		err := b.repinAt(oldMapPath, b.Path())
		if err != nil {
			return fmt.Errorf("error repinning old map %s to %s, err=%w", oldMapPath, b.Path(), err)
		}
	}

	if err := b.Open(); err == nil {
		// Get the existing map info
		mapInfo, err := GetMapInfo(b.fd)
		if err != nil {
			return fmt.Errorf("error getting map info of the pinned map %w", err)
		}

		if b.MaxEntries == mapInfo.MaxEntries {
			return nil
		}

		// store the old fd
		b.oldfd = b.MapFD()
		b.oldSize = mapInfo.MaxEntries

		err = b.repinAt(b.Path(), oldMapPath)
		if err != nil {
			return fmt.Errorf("error migrating the old map %w", err)
		}
		copyData = true
		// Do not close the oldfd if the map is updated by the BPF programs.
		if !b.UpdatedByBPF {
			defer func() {
				b.oldfd.Close()
				b.oldfd = 0
			}()
		}
	}

	logrus.Debug("Map didn't exist, creating it")
	cmd := exec.Command("bpftool", "map", "create", b.versionedFilename(),
		"type", b.Type,
		"key", fmt.Sprint(b.KeySize),
		"value", fmt.Sprint(b.ValueSize),
		"entries", fmt.Sprint(b.MaxEntries),
		"name", b.VersionedName(),
		"flags", fmt.Sprint(b.Flags),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logrus.WithField("out", string(out)).Error("Failed to run bpftool")
		return err
	}
	b.fd, err = GetMapFDByPin(b.versionedFilename())
	if err == nil {
		b.fdLoaded = true
		// Copy data from old map to the new map
		if copyData {
			err := b.copyFromOldMap()
			if err != nil {
				logrus.WithError(err).Error("error copying data from old map")
				return err
			}
			// Delete the old pin if the map is not updated by BPF programs.
			// Data from old map to new map will be copied once all the bpf
			// programs are installed with the new map.
			if !b.UpdatedByBPF {
				os.Remove(b.Path() + "_old")
			}

		}
		logrus.WithField("fd", b.fd).WithField("name", b.versionedFilename()).
			Info("Loaded map file descriptor.")
	}
	return err
}

func RepinMap(name string, filename string) error {
	cmd := exec.Command("bpftool", "map", "list", "-j")
	out, err := cmd.Output()
	if err != nil {
		return errors.Wrap(err, "bpftool map list failed")
	}
	logrus.WithField("maps", string(out)).Debug("Got map metadata.")

	var maps []bpftoolMapMeta
	err = json.Unmarshal(out, &maps)
	if err != nil {
		return errors.Wrap(err, "bpftool returned bad JSON")
	}

	for _, m := range maps {
		if m.Name == name {
			// Found the map, try to repin it.
			cmd := exec.Command("bpftool", "map", "pin", "id", fmt.Sprint(m.ID), filename)
			return errors.Wrap(cmd.Run(), "bpftool failed to repin map")
		}
	}

	return os.ErrNotExist
}
