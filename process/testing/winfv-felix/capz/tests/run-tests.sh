#!/bin/bash
set -ex

# Get the absolute path of the script.
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
TEST_BASE_DIR="$SCRIPT_DIR/.."

: ${KUBECONFIG_FILE:=$TEST_BASE_DIR/kubeconfig}
: ${KUBECTL_FILE:=$TEST_BASE_DIR/bin/kubectl}
: ${KCAPZ:="${KUBECTL_FILE} --kubeconfig=${KUBECONFIG_FILE}"}

# We'd like to copy over the files we need from the base directory to local directory.
# This will make the tests more self contained and have less impact on the CAPZ base code.
cp $TEST_BASE_DIR/ssh-node.sh ${SCRIPT_DIR}
cp $TEST_BASE_DIR/scp-to-node.sh ${SCRIPT_DIR}

# Prepare Windows nodes. Pull all images in advance.
WIN_NODE_IPS=$(${KCAPZ} get nodes -o wide -l kubernetes.io/os=windows --no-headers | awk '{print $6}' | awk -F '.' '{print $4}' | sort)
for n in ${WIN_NODE_IPS}
do
  ./scp-to-node.sh $n ./prepare-windows-nodes.ps1 c:\\k\\prepare-windows-nodes.ps1
  ./ssh-node.sh $n "c:\\k\\prepare-windows-nodes.ps1"
done

# Update labels of Windows nodes and create test pods.
index=1
WIN_NODES_NAMES=$(${KCAPZ} get nodes -o wide -l kubernetes.io/os=windows --no-headers | awk '{print $1}' | sort)
for n in ${WIN_NODES_NAMES}
do
  ${KCAPZ} --overwrite=true label node $n test.connection.windows.node=node$index
  index=$((index + 1))
done

${KCAPZ} create ns demo || true
${KCAPZ} apply -R -f ${SCRIPT_DIR}/tests/connections/infra/

${KCAPZ} wait --for=condition=Ready pods --all --namespace=demo --timeout=60s

# Start to run the tests.
TESTS_TO_RUN="tests"
#TESTS_TO_RUN="tests.connections.tests.test_connections:TestWindowsConnections.test_windows_pod_to_windows_service_name"

TEST_CONTAINER_NAME="calico/test:latest-amd64"

TEST_IMAGE=$(docker images | grep "calico/test" | cut -d ' ' -f1)
if [ -z "${TEST_IMAGE}" ]; then
  mkdir -p tests/calico_test
  pushd tests/calico_test || exit 1
  curl -sfL --retry 3 --remote-name-all https://raw.githubusercontent.com/projectcalico/calico/master/node/calico_test/{Dockerfile,requirements.txt}

  # Add openssh since it is required by connection tests.
  sed -i '/curl \\/a \    openssh \\' Dockerfile

  # Legacy builder from docker.io is installed by create-windows-nodes.sh on Ubuntu runners.
  # FIXME remove `--build-arg TARGETARCH=amd64` once we update to BuildKit buildx command.
  docker build --pull --build-arg ETCD_VERSION=v3.5.6 --build-arg TARGETARCH=amd64 -t ${TEST_CONTAINER_NAME} -f Dockerfile .
  popd || exit 1
fi

# Use sed to replace any .sshkey file path with /code/.sshkey.
# These helper scripts will be used to run inside the test container. 
sed -i 's#[^ ]*/\.sshkey#/code/.sshkey#g' ./ssh-node.sh ./scp-to-node.sh

# Fix error: Pseudo-terminal will not be allocated because stdin is not a terminal when ./ssh-node.sh 
# being called from python test script.
sed -i 's/-t /-tt /' ./ssh-node.sh

docker run --rm \
  -v "${SCRIPT_DIR}:/code" \
  -v "${TEST_BASE_DIR}/.sshkey:/code/.sshkey" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${KUBECONFIG_FILE}:/root/.kube/config" \
  -v "${KUBECTL_FILE}:/bin/kubectl" \
  --privileged \
  --net host \
  ${TEST_CONTAINER_NAME} \
  sh -c "echo 'container started..' && cd /code/tests/connections && nosetests ${TESTS_TO_RUN} -v --nocapture --with-xunit --xunit-file='/code/tests/report/connections-tests.xml' --with-timer"

EXIT_CODE=$?
echo "Windows connections tests exit code was ${EXIT_CODE}"

trigger="${HOME}/connections-test-done"
if [ -f "$trigger" ]; then
  echo "[CALICO_DEBUG] sleep until $trigger been removed." && while [ -f "$trigger" ]; do sleep 10; done
  echo "[CALICO_DEBUG] continue..."
fi

rm ./ssh-node.sh ./scp-to-node.sh
exit ${EXIT_CODE}
