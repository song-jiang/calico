// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package main

import (
	"flag"
	"fmt"
	"time"

	ebpfwin "github.com/projectcalico/calico/felix/bpf/libbpfwin"
)

func main() {
	// progID := ebpfwin.RunProgram()
	// fmt.Printf("From main.go: ebpfwin test RunProgram fd: %d\n\n", progID)

	// result := ebpfwin.RunAnotherProgram()
	// fmt.Printf("From main.go: ebpfwin test RunAnotherProgram return code: %d\n", result)

	/*
		err := ebpfwin.ObjectTest("c:\\k\\xdp.o", "calico_xdp_norm_pol_tail")
		if err != nil {
			fmt.Printf("From main.go test obj %v", err)
			return
		}
	*/

	num := flag.Int("n", 0, "network interface index")
	flag.Parse()
	n := *num

	_, err := ebpfwin.LoadXDPObject("c:\\k\\xdp.o", n, false)
	if err != nil {
		fmt.Printf("From main.go load xdp object %v", err)
		return
	}

	err = ebpfwin.MapTest()
	if err != nil {
		fmt.Printf("From main.go map test %v", err)
		return
	}

	for {
		fmt.Print("sleep 10 seconds\n")
		time.Sleep(10 * time.Second)
	}

}
