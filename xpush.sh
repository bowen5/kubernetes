make WHAT=cmd/hyperkube
export VERSION=v1.13.11-vnet"$1"
export REGISTRY=bowanacr.azurecr.io
export HYPERKUBE_BIN=$(pwd)/_output/bin/hyperkube
make -C cluster/images/hyperkube push

