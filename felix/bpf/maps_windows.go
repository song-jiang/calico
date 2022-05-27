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
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/libbpfwin"
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
	if b.fdLoaded {
		return nil
	}

	log.Info("Song 01: Map didn't exist, creating it")
	fd, err := libbpfwin.CreateMap(
		b.Type,
		b.KeySize,
		b.ValueSize,
		b.MaxEntries,
		uint32(b.Flags),
	)

	if err != nil {
		log.Infof("create map failed with err: %v", err)
		return err
	}

	b.fd = MapFD(fd)
	b.fdLoaded = true
	log.WithField("fd", b.fd).WithField("name", b.versionedFilename()).
		Info("Loaded map file descriptor.")

	return nil
}

func RepinMap(name string, filename string) error {
	return nil
}
