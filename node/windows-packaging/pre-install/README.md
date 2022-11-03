# Workaround on node reboot and kubelet lost connection.
This directory contains scripts which is a workaround to fix [trouble shooting calico](https://projectcalico.docs.tigera.io/getting-started/windows-calico/troubleshoot#:~:text=SecurityProtocolType%5D%3A%3ATls12-,Kubelet%20persistently%20fails%20to%20contact%20the%20API%20server,-If%20kubelet%20is)

## Steps to repo the issue.
- Node get restarted with kubelet and Calico running.

- kubelet started on the node. 

- Calico services started to run. It detected a node reboot. This would trigger Calico removes old networks and creates vswitch. 

- kubelet connection got broken for a few seconds and for some reason never get recovered.

## Workaround
Run the pre-create-external.ps1 script in the directory in the node provision process.
