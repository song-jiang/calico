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

func (b *PinnedMap) Open() error {
	// Do nothing on Windows for now.
	return nil
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
	copyData := false
	if b.fdLoaded {
		return nil
	}

	// In case felix restarts in the middle of migration, we might end up with
	// old map. Repin the old map and let the map creation continue.
	// Do nothing for now on Windows.

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
	return nil
}
