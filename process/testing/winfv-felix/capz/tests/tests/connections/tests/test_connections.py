# Copyright (c) 2020 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import subprocess
import time

from tests.connections.test_base import TestBase
from tests.connections.utils.utils import (
    retry_until_success,
    DiagsCollector,
    kubectl,
    node_info,
    run,
)

_log = logging.getLogger(__name__)
nginx_pod_port = 8080

# WindowsResources holds methods to setup/cleanup Windows testing enviroment.
class WindowsResources(object):
    #
    #                 +--------------------+----------------------+------------------+
    #                 |                    |                      |                  |
    #         +--------------+  +-----------------+     +----------------+  +----------------+
    #         | linux node   |  | linux node      |     | Windows node   |  | Windows node   |
    #         |              |  |                 |     |                |  |                |
    #         | POD: nginx   |  | POD: nginx      |     | POD: porter    |  | POD: porter    |
    #         |              |  |      busybox    |     |      powershell|  |                |
    #         +--------------+  +-----------------+     +----------------+  +----------------+

    def setup(self):
        (
            self.linux_nodes,
            self.linux_ips,
            self.windows_nodes,
            self.windows_ips,
        ) = node_info()

        # Set up window ssh command like "/code/ssh-node.sh 6"
        self.node1_winrm = "/code/ssh-node.sh %s" % self.windows_ips[0].split('.')[-1]
        self.node2_winrm = "/code/ssh-node.sh %s" % self.windows_ips[1].split('.')[-1]

        # Get Windows Info and pull/tag/fix windows image.
        self.calico_info = {}
        cmd = "$info = Get-HnsNetwork ; $info.Type"
        info = run("%s '%s'" % (self.node1_winrm, cmd))
        self.calico_info["vxlan"] = info.find("Overlay") != -1
        _log.info("Windows Calico Information - %s", self.calico_info)

        # Get the container runtime version. We'll assume both Windows nodes use
        # the same runtime.
        self.container_runtime = kubectl(
            "get node %s -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}'"
            % self.windows_nodes[0]
        )

        _log.info("Container runtime version: %s", self.container_runtime)

        kubectl(
            "--overwrite=true label node %s test.connection.windows.node=node1"
            % self.windows_nodes[0]
        )
        kubectl(
            "--overwrite=true label node %s test.connection.windows.node=node2"
            % self.windows_nodes[1]
        )

        kubectl("create ns demo")
        kubectl("apply -R -f infra/")
        time.sleep(1)

    def show(self):
        _log.info("linux nodes %s, ips %s", self.linux_nodes, self.linux_ips)
        _log.info("windows nodes %s, ips %s", self.windows_nodes, self.windows_ips)

    def cleanup(self):
        kubectl("label node %s test.connection.windows.node-" % self.windows_nodes[0])
        kubectl("label node %s test.connection.windows.node-" % self.windows_nodes[1])
        kubectl("delete ns demo")

    def get_test_config(self):
        self.nginx_svc_name = "nginx.demo.svc.cluster.local"
        self.porter_svc_name = "porter.demo.svc.cluster.local"
        self.porter_svc_shortname = "porter"

        self.nginx_node_port = kubectl(
            "get svc nginx -n demo -o jsonpath='{.spec.ports[0].nodePort}'"
        )
        self.porter_node_port = kubectl(
            "get svc porter -n demo -o jsonpath='{.spec.ports[0].nodePort}'"
        )

        if self.container_runtime.startswith("containerd") :
            output = run(
                "%s 'ctr.exe -n k8s.io containers list' | grep servercore | cut -d ' ' -f1"
                % self.node1_winrm
            )
        else:
            output = run(
                "%s 'docker ps -a' | grep powershell.exe | cut -d ' ' -f1"
                % self.node1_winrm
            )
        # Remove warning lines.
        # Iterate through each line in the output
        for line in output.splitlines():
            # Check if the line is a hexadecimal string
            if all(c in "0123456789abcdefABCDEF" for c in line.strip()):
                self.pwsh_container = line
                break
        _log.info("pwsh container: '%s'", self.pwsh_container)

        self.nginx_pod_ip = kubectl(
            "get endpoints nginx -n demo -o jsonpath='{.subsets[0].addresses[0].ip}'"
        )
        pod_ip = kubectl(
            "get endpoints porter -n demo -o jsonpath='{.subsets[0].addresses[0].ip}'"
        )
        self.porter_pod_ip0 = kubectl(
            "get endpoints porter -n demo -o jsonpath='{.subsets[*].addresses[?(@.nodeName==\"%s\")].ip}'"
            % self.windows_nodes[0]
        )
        self.porter_pod_ip1 = kubectl(
            "get endpoints porter -n demo -o jsonpath='{.subsets[*].addresses[?(@.nodeName==\"%s\")].ip}'"
            % self.windows_nodes[1]
        )
        _log.info(
            "nginx endpoint %s. porter endpoints %s, %s"
            % (self.nginx_pod_ip, self.porter_pod_ip0, self.porter_pod_ip1)
        )

    def test_linux_pod_to_target(self, target):
        kubectl("exec -t busybox -n demo -- wget %s -O -" % target)

    def test_windows_pod_to_target(self, target):
        if self.container_runtime.startswith("containerd") :
            cmd = "ctr.exe -n k8s.io tasks exec --exec-id 1 %s powershell.exe -command curl %s -UseBasicParsing" % (
                self.pwsh_container,
                target,
            )
        else:
            cmd = "docker exec -t %s powershell.exe -command curl %s -UseBasicParsing" % (
                self.pwsh_container,
                target,
            )
        print("run command: %s" % cmd)
        output = run("%s '%s'" % (self.node1_winrm, cmd))
        self.can_connect(output)

    def test_windows_node_to_target(self, target):
        cmd = "powershell.exe -command curl %s -UseBasicParsing" % target
        output = run("%s '%s'" % (self.node1_winrm, cmd))
        self.can_connect(output)

    def wait_until_containerd_cleanup(self):
        if self.container_runtime.startswith("containerd") :
            def check_if_container_gone():
                _log.info("Check if servercore container is still there...")
                container = run(
                    "%s 'ctr.exe -n k8s.io containers list' | grep servercore | cut -d ' ' -f1"
                    % self.node1_winrm
                )
                if container:
                    _log.info("servercore container still there: %s", container)
                    raise Exception("servercore container still there")
                _log.info("servercore container gone")

            retry_until_success(
                check_if_container_gone, retries=20, wait_time=3
            )

    @staticmethod
    def can_connect(result):
        if result.find("HTTP/1.1 200 OK") != -1:
            _log.info("connection has been made.")
        else:
            _log.warning("failed to connect, when connection was expected")
            raise self.ConnectionError

    class ConnectionError(Exception):
        pass


class TestAllRunning(TestBase):
    def test_kubesystem_pods_running(self):
        with DiagsCollector():
            self.check_pod_status("kube-system")


class TestWindowsConnections(TestBase):
    @classmethod
    def setUpClass(cls):
        cls.win = WindowsResources()
        cls.win.setup()
        cls.win.show()

    @classmethod
    def tearDownClass(cls):
        cls.win.cleanup()

    def setUp(self):
        TestBase.setUp(self)
        retry_until_success(
            self.check_pod_status, retries=120, wait_time=1, function_args=["demo"]
        )
        self.win.get_test_config()

    def tearDown(self):
        pass

    def test_windows_pod_lifecycle(self):
        # Delete all Windows pods.
        # They should be recreated and continue with rest of the test case.
        self.delete_and_confirm(name="pwsh", resource_type="pod", ns="demo")
        self.delete_and_confirm(name="node1-porter", resource_type="pod", ns="demo")
        self.delete_and_confirm(name="node2-porter", resource_type="pod", ns="demo")

        # Wait until containerd has cleaned up the servercore container before
        # continuing.
        self.win.wait_until_containerd_cleanup()

        kubectl("apply -R -f infra/")
        retry_until_success(
            self.check_pod_status, retries=120, wait_time=1, function_args=["demo"]
        )
        self.win.get_test_config()

    def test_windows_pod_to_linux_service_name(self):
        # Run 2 times to make sure all backend pods been accessed.
        for i in range(2):
            self.win.test_windows_pod_to_target(self.win.nginx_svc_name)

    def test_windows_pod_to_windows_service_name(self):
        # Run 2 times to make sure all backend pods been accessed.
        for i in range(2):
            self.win.test_windows_pod_to_target(self.win.porter_svc_name)

    def test_windows_pod_to_windows_service_shortname(self):
        # Run 2 times to make sure all backend pods been accessed.
        for i in range(2):
            self.win.test_windows_pod_to_target(self.win.porter_svc_shortname)

    def test_windows_node_to_local_pod(self):
        if self.win.calico_info["vxlan"]:
            self.skipTest("skipped test : Not working on Windows vxlan")
        self.win.test_windows_node_to_target(self.win.porter_pod_ip0)

    def test_windows_node_to_linux_pod(self):
        if self.win.calico_info["vxlan"]:
            self.skipTest("skipped test : Not working on Windows vxlan")
        target = "%s:%s" % (self.win.nginx_pod_ip, nginx_pod_port)
        self.win.test_windows_node_to_target(target)

    def test_windows_pod_to_linux_pod(self):
        target = "%s:%s" % (self.win.nginx_pod_ip, nginx_pod_port)
        self.win.test_windows_pod_to_target(target)

    def test_windows_pod_to_local_windows_pod(self):
        self.win.test_windows_pod_to_target(self.win.porter_pod_ip0)

    def test_windows_pod_to_remote_windows_pod(self):
        self.win.test_windows_pod_to_target(self.win.porter_pod_ip1)

    def test_windows_pod_to_google(self):
        self.win.test_windows_pod_to_target("-Uri http://google.com")

    def test_windows_pod_to_windows_node_port(self):
        self.skipTest("skipped test : Not working on Windows. Fix later")
        if self.win.calico_info["vxlan"]:
            self.skipTest("skipped test : Not working on Windows vxlan")
        for i in range(2):
            self.win.test_windows_pod_to_target(
                self.win.windows_ips[0] + ":" + self.win.porter_node_port
            )

    def test_linux_pod_to_windows_service(self):
        for i in range(2):
            self.win.test_linux_pod_to_target(self.win.porter_svc_shortname)

    def test_linux_pod_to_windows_pod(self):
        self.win.test_linux_pod_to_target(self.win.porter_pod_ip0)

    def test_linux_pod_to_windows_node_port(self):
        self.skipTest("skipped test : Not working on Windows. Fix later")
        for i in range(2):
            self.win.test_linux_pod_to_target(
                self.win.windows_ips[0] + ":" + self.win.porter_node_port
            )

    class ConnectionError(Exception):
        pass
