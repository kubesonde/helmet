/*
Copyright 2025 Helm-ET authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/samber/lo"
	logf "github.com/sirupsen/logrus"
	"helm.sh/helm/v3/pkg/cli"
	"helmet.io/pkg/boundaries"
	"helmet.io/pkg/core"
	"helmet.io/pkg/errors"
	"helmet.io/pkg/graph"
	"helmet.io/pkg/helm"
	"helmet.io/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	yaml "sigs.k8s.io/yaml"
)

var log = logf.WithFields(logf.Fields{
	"package": "main-script",
})

func init() {
	logf.SetFormatter(&logf.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
}

/*
This function wraps chart with its dependencies.
*/
func SecureWholeChart(settings *cli.EnvSettings, chartName string, releaseName string, output_dir string, dependencyLabelKey string, forceLoad bool) {
	clusterConfig := config.GetConfigOrDie()
	apiClient := lo.Must1(kubernetes.NewForConfig(clusterConfig))
	stats := core.ChartStats{}
	manifestList, err := helm.GetManifestList(settings, chartName, releaseName, forceLoad, output_dir)
	if err != nil {
		stats.Error = errors.StringToError(err.Error())
	}
	hw := types.Helmet{
		Manifests:      manifestList,
		HelmetLabel:    dependencyLabelKey,
		ManifestString: "",
	}

	config_available := os.Getenv("CONFIG_FILE")
	if len(config_available) == 0 {
		runWithDefaultConfig(hw, output_dir)
		fmt.Printf("Chart %s processed successfully using default configuration.\n Output folder: yaml", chartName)
	} else {
		runWithCustomConfig(hw, apiClient, config_available, output_dir)
		fmt.Printf("Chart %s processed successfully using %s configuration.\n Output folder: yaml", chartName, config_available)
	}
}

func runWithCustomConfig(hw types.Helmet, apiClient kubernetes.Interface, config_available string, output_dir string) {
	log.Info(fmt.Sprintf("Reading configuration file %s", config_available))
	content := lo.Must(boundaries.ReadHelmETConfigsFromYAML(config_available))
	ancestors, _ := graph.GetAcenstorsDescendants(hw.Manifests)
	generated_policies := boundaries.TemplatesToNetpol(content, apiClient, ancestors)

	networkPolicies := []string{}

	for _, netpol := range generated_policies {
		netpol_bytes := lo.Must(yaml.Marshal(netpol))
		cleaned_bytes := strings.Trim(strings.Trim(strings.ReplaceAll(string(netpol_bytes), "status: {}", ""), "\n"), " ")
		networkPolicies = append(networkPolicies, cleaned_bytes)
		core.WriteToList([]byte(cleaned_bytes), fmt.Sprintf("%s--netpol.yaml", netpol.Name), output_dir)
		log.Info(fmt.Sprintf("%s--netpol.yaml", netpol.Name))
	}

	output_data := helm.ManifestsToString(hw.Manifests)
	for _, netpol := range networkPolicies {
		output_data = fmt.Sprintf("%s\n---\n%s", output_data, netpol)
	}
	lo.Must0(core.WriteManifestList(hw.Manifests, output_dir))

	fmt.Println(output_data)
}

func runWithDefaultConfig(hw types.Helmet, output_dir string) {
	log.Info("No config available")
	updated_data := hw.ManifestString
	netpols := graph.ProcessChart(hw.Manifests)
	manifests := hw.Manifests
	log.WithField("policies", len(netpols)).Infof("Len policies: %d", len(netpols))

	for _, netpol := range netpols {
		netpol_str := string(lo.Must(yaml.Marshal(netpol)))
		netpol_str = strings.Trim(strings.Trim(strings.ReplaceAll(netpol_str, "status: {}", ""), "\n"), " ")
		updated_data += helm.MANIFEST_SEPARATOR + netpol_str
		manifestYaml := make(helm.HelmManifest)
		lo.Must0(yaml.Unmarshal([]byte(netpol_str), manifestYaml))
		manifests[fmt.Sprintf("%s.yaml", netpol.Name)] = manifestYaml
	}
	_, descendants := graph.GetAcenstorsDescendants(hw.Manifests)
	configs := boundaries.NetworkPoliciesToTemplate(netpols, descendants)
	lo.Must0(boundaries.WriteHelmETConfigsToYAML(configs, "config.yaml"))
	lo.Must0(core.WriteManifestList(manifests, output_dir))
	fmt.Println(updated_data)
}

func main() {
	output_dir := "yaml"

	chartName := flag.String("chartName", "bitnami/wordpress", "the chart name to run the tool with")

	releaseName := flag.String("release", "wordpress", "the name of the release")

	forceLoad := flag.Bool("forceLoad", true, "Force chart load, omitting ./yaml")

	flag.Parse()
	dependencyLabelKey := "helmet.io/chart"
	log.WithFields(logf.Fields{"chartName": *chartName, "releaseName": *releaseName, "forceLoad": *forceLoad}).Info("Cli variables")

	settings := cli.New()

	SecureWholeChart(settings, *chartName, *releaseName, output_dir, dependencyLabelKey, *forceLoad)
}
