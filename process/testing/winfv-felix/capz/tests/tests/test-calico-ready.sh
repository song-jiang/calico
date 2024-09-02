#!/bin/bash -e

# Kubernetes config file location
KUBECONFIG_FILE="${KUBECONFIG_FILE:=${HOME}/.kube/config}"
export KUBECONFIG=$KUBECONFIG_FILE
PROVISIONER="${PROVISIONER:=aws-kubeadm}"

function retry_kubectl() {
  kubectl_command=$1
  # With semaphore job, kubectl should at the right path.
  kube=$(command -v "${KUBECTL_BINARY}")
  if [[ "${kube}" == "" ]]; then
      echo "[ERROR] ${KUBECTL_BINARY} not found locally".
      exit 1
  fi
  kubectl_retries=3
  kubectl_success=1
  kubectl_output=""
  until [[ ${kubectl_success} -eq 0 ]] || [[ kubectl_retries -lt 1 ]]; do
    echo "Attempting to run ${kube} $kubectl_command, attempts remaining=$kubectl_retries"
    kubectl_output=$(eval "${kube} ${kubectl_command}")
    kubectl_success=$?
    ((kubectl_retries--))
    sleep 1
  done
  echo "${kubectl_output}"
  return ${kubectl_success}
}

CALICO_NS=$( (retry_kubectl "get ns" | grep calico-system >/dev/null 2>&1) && echo "calico-system" || echo "kube-system" )

echo "Running test-calico-ready.sh"
echo "Settings:"
echo "   KUBECONFIG_FILE=${KUBECONFIG_FILE}"
echo "   PROVISIONER=${PROVISIONER}"
echo "   KUBECTL_BINARY=${KUBECTL_BINARY}"
echo "   CALICO_NS=${CALICO_NS}"

echo "Check if Calico is ready...kubeconfig ${KUBECONFIG} calico ns ${CALICO_NS}"
while ! retry_kubectl "wait pod -l k8s-app=calico-node --for=condition=Ready -n ${CALICO_NS} --timeout=300s"; do
    # This happens when no matching resources exist yet,
    # i.e. immediately after application of the Calico YAML.
    retry_kubectl "get pod -o wide -n ${CALICO_NS}"
    sleep 5
done
# Check calico-kube-controllers is up
retry_kubectl "wait pod -l k8s-app=calico-kube-controllers --for=condition=Ready -n ${CALICO_NS} --timeout=300s"
# Check dns is up
if [[ ${PROVISIONER} == aws-openshift ]]; then
  echo "Checking for dns-operator, not kube-dns - this is openshift"
  retry_kubectl "wait deployment dns-operator --for=condition=Available -n openshift-dns-operator --timeout=300s"
else
  echo "Checking that kube-dns is up"
  retry_kubectl "wait pod -l k8s-app=kube-dns --for=condition=Ready -n kube-system --timeout=300s"
fi
echo "Calico is running."
echo

echo "Create test deployment..."
retry_kubectl "create ns demo"
retry_kubectl "apply -f $(dirname "$0")/connections/infra/busybox.yaml"
retry_kubectl "apply -f $(dirname "$0")/connections/infra/nginx.yaml"

echo "Wait for client and server pods to be ready..."
while ! retry_kubectl "wait pod -l pod-name=busybox -n demo --for=condition=Ready --timeout=300s"; do
    sleep 5
done
while ! retry_kubectl "wait pod -l app=nginx -n demo --for=condition=Ready --timeout=300s"; do
    sleep 5
done
echo "client and server pods are running."
echo

# Run connection test
function test_connection() {
  local svc="nginx"
  output=$(retry_kubectl "exec busybox -n demo -- wget $svc -T 5 -O -")
  if [[ $output != *"Welcome to nginx"* ]]; then
    echo "[ERROR] connection to $svc service failed"
    return 1
  else
    echo "[INFO] connection to $svc service succeeded"
    return 0
  fi
}

retries=10
success=1
until [[ ${success} -eq 0 ]] || [[ retries -lt 1 ]]
do
  echo "Attempting connection test, attempts remaining=$retries"
  success=test_connection
  ((retries--))
  sleep 1
done

retry_kubectl "delete ns demo" || true
if [[ ${success} == 1 ]]; then
   exit 1
fi
echo "[INFO] Calico is ready. Networking works fine on linux side."
