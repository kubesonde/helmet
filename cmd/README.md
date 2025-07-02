# Standalone
This folder contains the script to run Helm-ET as a standalone.
## How to run 
To run Helm-ET, you just need to execute the script on this folder:
`go run script.go -chartName "chartName" -release "release" -forceLoad=true`

For example:
`go run script.go -chartName "bitnami/wordpress" -release "wordpress" -forceLoad=true`
> Note: Before processing the chart, make sure to download the repository (e.g,: `helm repo add bitnami https://charts.bitnami.com/bitnami`)

The output of the execution is stored in the `./yaml` folder. 
### Custom configuration
To run Helm-ET with the custom configuration, you need to specify the environment variable `CONFIG_FILE`. For example:
`CONFIG_FILE=/mypath/myconfig.yaml go run script.go -chartName "bitnami/wordpress" -release "wordpress" -forceLoad=true`

More information about the custom configuration can be found at [Custom Configuration](../docs/custom_configuration.md)
