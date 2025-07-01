# Postrender

This folder contains the necessary toolings to create the Helm-ET postrenderer.

## Build

Run `make` to build the postrenderer.

## Install


Example: `helm install wordpress bitnami/wordpress --timeout 10m --post-renderer ./postrender`

> Note: Before installing the chart, make sure to download the repository (e.g,: `helm repo add bitnami https://charts.bitnami.com/bitnami`)
> 
## Uninstall

Run `make stop` to uninstall the resources. 
