CURRENT_DIR=$(shell pwd)
BINDIR?=bin
ARCH?=amd64

###############################################################################
# Cluster management
###############################################################################
.PHONY: create-cluster
create-cluster: $(BINDIR)/kind $(BINDIR)/kubectl $(BINDIR)/clusterctl
	@echo 'Creating cluster $(CLUSTER_NAME_CAPZ) ...'
	./create-cluster.sh
	make generate-helpers

.PHONY: delete-cluster
delete-cluster: $(BINDIR)/kind $(BINDIR)/kubectl
	@echo 'Azure resources for cluster $(CLUSTER_NAME_CAPZ) will now be deleted, this can take up to 20 minutes'
	$(BINDIR)/kubectl delete cluster $(CLUSTER_NAME_CAPZ)
	$(BINDIR)/kind delete cluster
	rm kubeconfig

.PHONY: install-calico
install-calico:
	./install-calico.sh

###############################################################################
# Utilities management
###############################################################################
.PHONY: generate-helpers
generate-helpers: 
	./generate-helpers.sh

$(BINDIR): 
	mkdir -p $(BINDIR)

$(BINDIR)/kind: $(BINDIR)
	GOBIN=$(CURRENT_DIR)/$(BINDIR) go install sigs.k8s.io/kind@v0.11.1

$(BINDIR)/kubectl: $(BINDIR)
	curl -L https://storage.googleapis.com/kubernetes-release/release/v1.22.0/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $(BINDIR)/kubectl

$(BINDIR)/clusterctl: $(BINDIR)
	curl -L https://github.com/kubernetes-sigs/cluster-api/releases/download/v1.1.2/clusterctl-linux-amd64 -o $(BINDIR)/clusterctl
	chmod +x $(BINDIR)/clusterctl
	$(BINDIR)/clusterctl version

clean: 
	# Clean files
	rm -f kubeconfig 
	rm -f *.yaml 
	rm -f .sshkey .sshkey.pub
	rm -rf ${BINDIR}
