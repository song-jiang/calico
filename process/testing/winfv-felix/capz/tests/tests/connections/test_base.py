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
import json
import logging
import os
import subprocess
import time
from pprint import pformat
from unittest import TestCase

from deepdiff import DeepDiff
from kubernetes import client, config

from utils.utils import kubectl, retry_until_success

logger = logging.getLogger(__name__)
first_log_time = None


class TestBase(TestCase):

    """
    Base class for test-wide methods.
    """

    def setUp(self):
        """
        Clean up before every test.
        """
        self.cluster = self.k8s_client()

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

    @staticmethod
    def assert_same(thing1, thing2):
        """
        Compares two things.  Debug logs the differences between them before
        asserting that they are the same.
        """
        assert cmp(thing1, thing2) == 0, (
            "Items are not the same.  Difference is:\n %s"
            % pformat(DeepDiff(thing1, thing2), indent=2)
        )

    @staticmethod
    def writejson(filename, data):
        """
        Converts a python dict to json and outputs to a file.
        :param filename: filename to write
        :param data: dictionary to write out as json
        """
        with open(filename, "w") as f:
            text = json.dumps(data, sort_keys=True, indent=2, separators=(",", ": "))
            logger.debug("Writing %s: \n%s" % (filename, text))
            f.write(text)

    @staticmethod
    def log_banner(msg, *args, **kwargs):
        global first_log_time
        time_now = time.time()
        if first_log_time is None:
            first_log_time = time_now
        time_now -= first_log_time
        elapsed_hms = "%02d:%02d:%02d " % (
            time_now / 3600,
            (time_now % 3600) / 60,
            time_now % 60,
        )

        level = kwargs.pop("level", logging.INFO)
        msg = elapsed_hms + str(msg) % args
        banner = "+" + ("-" * (len(msg) + 2)) + "+"
        logger.log(level, "\n" + banner + "\n" "| " + msg + " |\n" + banner)

    @staticmethod
    def k8s_client():
        config.load_kube_config(os.environ.get("KUBECONFIG"))
        return client.CoreV1Api()

    def check_pod_status(self, ns):
        pods = self.cluster.list_namespaced_pod(ns)

        for pod in pods.items:
            logger.info(
                "%s\t%s\t%s",
                pod.metadata.name,
                pod.metadata.namespace,
                pod.status.phase,
            )
            if pod.status.phase != "Running" and pod.status.phase != "Succeeded":
                logger.info("pod no good %s = %s" % (pod.metadata.name, pod.status.phase))
                kubectl(
                    "describe po %s -n %s" % (pod.metadata.name, pod.metadata.namespace)
                )
            assert pod.status.phase == "Running" or pod.status.phase == "Succeeded"

    def wait_until_exists(self, name, resource_type, ns="default"):
        retry_until_success(
            kubectl, function_args=["get %s %s -n %s" % (resource_type, name, ns)]
        )

    def delete_and_confirm(self, name, resource_type, ns="default"):
        try:
            kubectl("delete %s %s -n %s" % (resource_type, name, ns))
        except subprocess.CalledProcessError:
            pass

        def is_it_gone_yet(res_name, res_type):
            try:
                kubectl("get %s %s -n %s" % (res_type, res_name, ns), logerr=False)
                raise self.StillThere
            except subprocess.CalledProcessError:
                # Success
                pass

        retry_until_success(
            is_it_gone_yet,
            retries=10,
            wait_time=10,
            function_args=[name, resource_type],
        )

    class StillThere(Exception):
        pass
