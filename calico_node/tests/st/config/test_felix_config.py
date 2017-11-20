# Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
import time
from functools import partial

import yaml
from tests.st.test_base import TestBase, HOST_IPV4
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.utils import log_and_run, retry_until_success, \
    handle_failure, clear_on_failures, add_on_failure, wipe_etcd

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)

POST_DOCKER_COMMANDS = [
    "docker load -i /code/calico-node.tar",
]


class TestFelixConfig(TestBase):
    """
    Tests felix configurations setup by calicoctl.
    """
    hosts = None

    @classmethod
    def setUpClass(cls):
        # Wipe etcd once before any test in this class runs.
        _log.debug("Wiping etcd")
        wipe_etcd(HOST_IPV4)

        # Test felix configurations.

        # Create two hosts.
        cls.hosts = []
        cls.host1 = DockerHost("cali-host1",
                               additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                               post_docker_commands=POST_DOCKER_COMMANDS,
                               start_calico=False)
        cls.host1_hostname = cls.host1.execute("hostname")
        cls.host2 = DockerHost("cali-host2",
                               additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                               post_docker_commands=POST_DOCKER_COMMANDS,
                               start_calico=False)
        cls.host2_hostname = cls.host2.execute("hostname")
        cls.hosts.append(cls.host1)
        cls.hosts.append(cls.host2)

        # Start calico node on hosts.
        for host in cls.hosts:
            host.start_calico_node()

        _log.info("host1 IP: %s , host2 IP: %s", cls.host1.ip, cls.host2.ip)

        clear_on_failures()
        add_on_failure(cls.host1.log_extra_diags)
        add_on_failure(cls.host2.log_extra_diags)

    @handle_failure
    def test_failsafe_inbound(self):
        """
        Test failsafe inbound configuration.
        """
        random = {"udp": [70], "tcp": [3000, 5000]}
        default = {"udp": [68], "tcp": [22, 179, 2379, 2380, 6666, 6667]}

        # Test random and default ports can be accessed with no host endpoints setup.
        self.run_failsafe(default, True)
        self.run_failsafe(random, True)

        # With host endpoints setup. Default ports can be accessed.
        # But random ports can not.
        self.add_host_iface(self.host1_hostname, self.host1.ip)
        self.run_failsafe(default, True)
        self.run_failsafe(random, False)

        # Update felix config and check again.
        self.add_felix_failsafe_config("default", random, "inbound")
        self.run_failsafe(default, False)
        self.run_failsafe(random, True)

        # Put default back for host1.
        self.add_felix_failsafe_config("node.%s" % self.host1_hostname, default, "inbound")
        self.run_failsafe(default, True)
        self.run_failsafe(random, False)

        # Put default back for all.
        self.add_felix_failsafe_config("default", default, "inbound")
        return

    @handle_failure
    def test_failsafe_outbound(self):
        """
        Test failsafe outbound configuration.
        """
        # We need to put 2379 into random because felix need to connect to etcd.
        random = {"udp": [70], "tcp": [2379, 3000, 5000]}
        default = {"udp": [53, 67], "tcp": [179, 2379, 2380, 6666, 6667]}

        # Test random and default ports can be accessed with no host endpoints setup.
        self.run_failsafe(default, True)
        self.run_failsafe(random, True)

        # With host endpoints setup. Default ports can be accessed.
        # But random ports can not.
        self.add_host_iface(self.host2_hostname, self.host2.ip)
        self.run_failsafe(default, True)
        self.run_failsafe(random, False)

        # Update felix config and check again.
        self.add_felix_failsafe_config("default", random, "outbound")
        self.run_failsafe(default, False)
        self.run_failsafe(random, True)

        # Put default back for host2.
        self.add_felix_failsafe_config("node.%s" % self.host2_hostname, default, "outbound")
        self.run_failsafe(default, True)
        self.run_failsafe(random, False)

        # Put default back for all.
        self.add_felix_failsafe_config("default", default, "outbound")
        return

    @handle_failure
    def test_log_file(self):
        """
        Test Log file configuration.
        """
        conf_name = "node.%s" % self.host1_hostname
        default = "/var/log/calico/felix/current"

        # Check default log file is good.
        retry_until_success(self._get_check_file_func(True, default, "INFO"),
                            retries=3)
        retry_until_success(self._get_check_file_func(False, default, "DEBUG"),
                            retries=3)

        # Change severity to DEBUG.
        self.add_felix_config(conf_name, {'LogSeverityFile': 'DEBUG'})
        retry_until_success(self._get_check_file_func(True, default, "DEBUG"),
                            retries=3)

        # Change log file and severity to FATAL.
        new_path = "/var/log/calico/st_test0"
        self.add_felix_config(conf_name, {'logFilePath': new_path, 'LogSeverityFile': 'FATAL'})
        self.restart_felix_no_config_file(self.host1)

        # Dont expect FATAL or WARNING message from new log file.
        retry_until_success(self._get_check_file_func(False, new_path, "WARNING"),
                            retries=3)
        retry_until_success(self._get_check_file_func(False, new_path, "FATAL"),
                            retries=3)

        # Send a termination signal. We should see FATAL but not WARNING.
        self.restart_felix_no_config_file(self.host1)
        retry_until_success(self._get_check_file_func(False, new_path, "WARNING"),
                            retries=3)
        retry_until_success(self._get_check_file_func(True, new_path, "FATAL"),
                            retries=3)

        # Change log file and severity to WARNING and send termination signal.
        new_path = "/var/log/calico/st_test1"
        self.add_felix_config(conf_name, {'logFilePath': new_path, 'LogSeverityFile': 'WARNING'})
        self.restart_felix_no_config_file(self.host1)

        # Dont expect FATAL or WARNING message from new log file.
        retry_until_success(self._get_check_file_func(False, new_path, "WARNING"),
                            retries=3)
        retry_until_success(self._get_check_file_func(False, new_path, "FATAL"),
                            retries=3)

        # Expect both FATAL and WARNING message from new log file.
        self.restart_felix_no_config_file(self.host1)
        retry_until_success(self._get_check_file_func(True, new_path, "WARNING"),
                            retries=3)
        retry_until_success(self._get_check_file_func(True, new_path, "FATAL"),
                            retries=3)

        # Should have error message when log severity is WARING.
        self.remove_ipset_command(self.host1)
        retry_until_success(self._get_check_file_func(True, new_path, "ERROR"),
                            retries=20)
        self.restore_ipset_command(self.host1)

        # Restore log config
        self.add_felix_config(conf_name, {'logFilePath': default, 'LogSeverityFile': 'INFO'})
        self.restart_felix_no_config_file(self.host1)

    @staticmethod
    def remove_ipset_command(host):
        cmd = "docker exec calico-node mv /usr/sbin/ipset /usr/sbin/ipset.backup"
        host.execute(cmd)

    @staticmethod
    def restore_ipset_command(host):
        cmd = "docker exec calico-node mv /usr/sbin/ipset.backup /usr/sbin/ipset"
        host.execute(cmd)

    def restart_felix_no_config_file(self, host):
        _log.info("Try to remove default felix config file and restart felix")
        cmd = "docker exec calico-node rm -f /etc/calico/felix.cfg"
        host.execute(cmd)
        cmd = "docker exec calico-node pkill -f calico-felix"
        host.execute(cmd)

        for retry in range(5):
            result = host.execute("docker exec calico-node ps -a | grep -c calico-felix || exit 0")
            if result == "1":
                _log.info("calico-felix restarted.")
                return
            else:
                _log.info("retry [%s] calico-felix waiting for restart", retry)
                time.sleep(1)
        self.fail("Failed to restart felix in 5 seconds.")

    def _get_check_file_func(self, expect, log_file, keyword=""):
        func = partial(self.log_check_file, self.host1, expect, log_file, keyword)
        return func

    def log_check_file(self, host, expect, log_file, keyword=""):
        _log.info("Check log file %s, keywords %s, expect %s", log_file, keyword, expect)
        cmd = "test -e %s ; echo $?" % log_file
        result = host.execute(cmd)
        if not result == "0":
            self.fail(("Log file %s not exists." % log_file))

        if keyword != "":
            cmd = "grep -c %s %s || exit 0" % (keyword, log_file)
            result = host.execute(cmd, raise_exception_on_failure=False)
            _log.info("Check keywords result is %s", result)
            if result == "0" and expect:
                self.fail(("Log file %s does not contain keyword %s which is not "
                           "expected." % (log_file, keyword)))
            if result != "0" and not expect:
                self.fail(("Log file %s contains keyword %s which is not "
                           "expected." % (log_file, keyword)))

    def setUp(self):
        # Override the per-test setUp to avoid wiping etcd; instead only clean up the data we
        # added.
        self.remove_host_endpoint()

    def tearDown(self):
        self.remove_host_endpoint()
        super(TestFelixConfig, self).tearDown()

    @classmethod
    def tearDownClass(cls):
        # Tidy up
        for host in cls.hosts:
            host.remove_workloads()
        for host in cls.hosts:
            # Just check CRITICAL message because some error messages are genenrated
            # by test cases.
            host.cleanup(err_words={"CRITICAL"})
            del host

        clear_on_failures()

    def add_host_iface(self, node_name, ip):
        host_endpoint_data = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'HostEndpoint',
            'metadata': {
                'name': 'host-int',
                'labels': {'nodeEth': 'host'}
            },
            'spec': {
                'node': node_name,
                'interfaceName': 'eth0',
                'expectedIPs': [str(ip)],
            }
        }
        self._apply_resources(host_endpoint_data, self.host2)

    def add_felix_config(self, name, spec):
        felix_config = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'FelixConfiguration',
            'metadata': {
                'name': name,
            },
            'spec': spec,
        }
        self._apply_resources(felix_config, self.host1)

    def add_felix_failsafe_config(self, name, failsafe, direction):
        # Convert to map list
        udp_ports = map(lambda x: {'protocol': 'UDP', 'port': x}, failsafe['udp'])
        tcp_ports = map(lambda x: {'protocol': 'TCP', 'port': x}, failsafe['tcp'])

        if direction == "inbound":
            spec = {'failsafeInboundHostPorts': udp_ports + tcp_ports}
        elif direction == "outbound":
            spec = {'failsafeOutboundHostPorts': udp_ports + tcp_ports}
        else:
            self.fail("Adding felix config with wrong 'direction' %s", direction)

        self.add_felix_config(name, spec)

    def run_failsafe(self, failsafe, expect_access):
        for k in failsafe:
            for port in failsafe[k]:
                if port != 179:  # port is already open by bird.
                    self.open_port(self.host1, port, k)

        for k in failsafe:
            for port in failsafe[k]:
                self.check_access_retry(expect_access, self.host2, self.host1, port, k)

    @staticmethod
    def open_port(host, port, protocal="tcp"):
        protocal_opt = "-u" if protocal == "udp" else ""
        cmd = "nc -l %s -p %s -e /bin/sh" % (protocal_opt, port)
        host.execute(cmd, raise_exception_on_failure=True, daemon_mode=True)

    def check_access_retry(self, expect_access, host_src, host_target, port, protocal="tcp"):
        msg = (" from %s to %s:%s %s, expect access %s" %
               (host_src.ip, host_target.ip, port, protocal, expect_access))
        for retry in range(3):
            passed = self.check_access(expect_access, host_src, host_target, port, protocal)
            if passed:
                _log.info("check access success!%s", msg)
                return
            else:
                _log.exception("retry [%s] check access failed!%s", retry, msg)
                time.sleep(1)
        self.fail(("check access failed!%s", msg))

    @staticmethod
    def check_access(expect_access, host_src, host_target, port, protocal="tcp"):
        protocol_opt = "-u" if protocal == "udp" else ""
        cmd = "echo \"hostname && exit\" | timeout -t 3 nc %s -w 1 %s %s" % \
              (protocol_opt, host_target.ip, port)
        remote_hostname = host_src.execute(cmd, raise_exception_on_failure=False)
        hostname = host_target.execute("hostname")
        _log.info("check access from %s to %s:%s %s, result is |%s|, "
                  "target hostname |%s|, expect access %s",
                  host_src.ip, host_target.ip, port, protocal,
                  remote_hostname, hostname, expect_access)

        # If port is 179, we are talking to bird.
        # If bird returns with a valid string, this means connection is successful.
        if port == 179 and remote_hostname is not None and len(remote_hostname) > 0:
            remote_hostname = hostname

        result = (hostname == remote_hostname)
        return result == expect_access

    def add_policy(self, policy_data):
        self._apply_resources(policy_data, self.host1)

    def remove_host_endpoint(self):
        self.delete_all("hostEndpoint")

    @classmethod
    def delete_all(cls, resource):
        # Grab all objects of a resource type
        objects = yaml.load(cls.hosts[0].calicoctl("get %s -o yaml" % resource))
        # and delete them (if there are any)
        if len(objects) > 0:
            _log.info("objects: %s", objects)
            if 'items' in objects and len(objects['items']) == 0:
                pass
            else:
                cls._delete_data(objects, cls.hosts[0])

    @classmethod
    def _delete_data(cls, data, host):
        _log.debug("Deleting data with calicoctl: %s", data)
        cls._exec_calicoctl("delete", data, host)

    @classmethod
    def _apply_resources(cls, resources, host):
        cls._exec_calicoctl("apply", resources, host)

    @staticmethod
    def _exec_calicoctl(action, data, host):
        # Delete creationTimestamp fields from the data that we're going to
        # write.
        for obj in data.get('items', []):
            if 'creationTimestamp' in obj['metadata']:
                del obj['metadata']['creationTimestamp']
        if 'metadata' in data and 'creationTimestamp' in data['metadata']:
            del data['metadata']['creationTimestamp']

        # Use calicoctl with the modified data.
        host.writefile("new_data",
                       yaml.dump(data, default_flow_style=False))
        host.calicoctl("%s -f new_data" % action)

    @classmethod
    def get_container_ip(cls, container_name):
        ip = log_and_run(
            "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s" %
            container_name)
        return ip.strip()
