repository=${repository:-"songtjiang"}
tag=${tag:-"01"}

curl -LO https://raw.githubusercontent.com/microsoft/SDN/0d7593e5c8d4c2347079a7a6dbd9eb034ae19a44//Kubernetes/windows/hns.psm1

docker buildx build --platform windows/amd64 --output=type=registry --pull -f Dockerfile.install -t $repository/capz-preinstall:$tag .
