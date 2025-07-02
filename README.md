
<p align="center">
<img src="docs/helmet.svg" alt="Helm-ET logo" style="width:40%; height:auto;">
</p>

# Helm-ET

![Go Tests](https://github.com/kubesonde/helmet/actions/workflows/test.yml/badge.svg)
![Golangci](https://github.com/kubesonde/helmet/actions/workflows/lint.yml/badge.svg)

This repository contains the source code for `Helm-ET` (Helm Edge Trimmer), a tool to automate the access control policy definition of helm charts.

## How to run 
Helm-ET can be used in two different flavours: 
  1. As a standalone binary
  2. As a helm [postrender hook](https://helm.sh/docs/topics/advanced/#post-rendering). 


## Building from source

Refer to the specific [README](./cmd/README.md) to build the standalone binary. 

For the postrender version, refer to the specific [README](./postrender/README.md).

> Note: The postrender version is the one used for testing the paper.

## Prerequisites
go > 1.18

## Testing

Unit tests are available as part of the source code. Run `make test` under in the main folder of this project.

## Documentation

Documentation of Helm-ET and a version of the paper are available under the [docs/](./docs/) folder
