repository=${repository:-"songtjiang"}
version=${version:-"01"}

docker buildx build --platform windows/amd64 --output=type=registry --pull --build-arg=BUILD_VERSION=$version -f Dockerfile.install -t $repository/ebpfwin-install:$version .
