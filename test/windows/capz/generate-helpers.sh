set -e 

: ${KUBECTL:=./bin/kubectl}

KCAPZ="${KUBECTL} --kubeconfig=./kubeconfig"

APISERVER=$(${KCAPZ} config view -o jsonpath='{.clusters[?(@.name == "win-capz")].cluster.server}' | awk -F/ '{print $3}' | awk -F: '{print $1}')
if [ -z "${APISERVER}" ] ; then
  echo "Failed to get apiserver public ip"
  exit -1
fi
echo
echo APISERVER: ${APISERVER}

${KCAPZ} get node -o wide

echo
echo "Generating helper files"
CONNECT_FILE="ssh-node.sh"
echo "#---------Connect to Instance--------" | tee ${CONNECT_FILE}
echo "#usage: ./ssh-node.sh 6 to ssh into 10.1.0.6" | tee -a ${CONNECT_FILE}
echo "#usage: ./ssh-node.sh 6 'Get-Service -Name kubelet' > output" | tee -a ${CONNECT_FILE}
echo ssh -t -i .sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o \'ProxyCommand ssh -i .sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p capi@${APISERVER}\' capi@10.1.0.\$1 \$2 | tee -a ${CONNECT_FILE}
chmod +x ${CONNECT_FILE}
echo

SCP_FILE="scp-node.sh"
echo "#---------Copy files to Instance--------" | tee ${SCP_FILE}
echo "#usage: ./scp-node.sh 6 kubeconfig c:\\\\k\\\\kubeconfig -- copy kubeconfig to 10.1.0.6" | tee -a ${SCP_FILE}
echo "#usage: ./scp-node.sh 6 images/ebpf-for-windows-c-temp.zip 'c:\\' -- copy temp zip to 10.1.0.6" | tee -a ${SCP_FILE}
echo scp -i .sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o \'ProxyCommand ssh -i .sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p capi@${APISERVER}\' \$2 capi@10.1.0.\$1:\$3 | tee -a ${SCP_FILE}
chmod +x ${SCP_FILE}
echo

SCP_FILE="scp-calico-log-from-node.sh"
echo "#---------Copy files to Instance--------" | tee ${SCP_FILE}
echo "#usage: ./scp-calico-log-from-node.sh 6 calico-felix.log" | tee -a ${SCP_FILE}
echo scp -i .sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o \'ProxyCommand ssh -i .sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p capi@${APISERVER}\' capi@10.1.0.\$1:c:/CalicoWindows/logs/\$2 . | tee -a ${SCP_FILE}
chmod +x ${SCP_FILE}
