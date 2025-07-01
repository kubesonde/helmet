package main

import (
	"flag"

	logf "github.com/sirupsen/logrus"

	"helm.sh/helm/v3/pkg/cli"
	"helmet.io/pkg/core"
)

var (
	log = logf.WithFields(logf.Fields{
		"package": "main-script",
	})
)

func init() {
	logf.SetFormatter(&logf.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
}

func main() {

	output_dir := "yaml"

	var chartName = flag.String("chartName", "bitnami/wordpress", "the chart name to run the tool with")

	var releaseName = flag.String("release", "wordpress", "the name of the release")

	var forceLoad = flag.Bool("forceLoad", true, "Force chart load, omitting ./yaml")

	flag.Parse()
	dependencyLabelKey := "helmet.io/chart"
	log.WithFields(logf.Fields{"chartName": *chartName, "releaseName": *releaseName, "forceLoad": *forceLoad}).Info("Cli variables")

	settings := cli.New()

	core.SecureWholeChart(settings, *chartName, *releaseName, output_dir, dependencyLabelKey, *forceLoad)

}
