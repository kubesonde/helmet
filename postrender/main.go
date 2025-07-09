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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"helmet.io/pkg/boundaries"
	"helmet.io/pkg/core"
	"helmet.io/pkg/graph"
	"helmet.io/pkg/helm"
	"helmet.io/pkg/logging"
	"helmet.io/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	yaml "sigs.k8s.io/yaml"
)

var (
	output_dir         = "output_dir"
	dependencyLabelKey = "helmet.io/chart"
	log                = logging.LOGGER.WithFields(logrus.Fields{
		"source": "postrender",
	})
)

func emptyFolder(folder string) {
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		lo.Must0(os.MkdirAll(folder, 0o750))
	}
	fldRead := lo.Must1(os.Open(filepath.Clean(folder)))
	files := lo.Must1(fldRead.Readdir(0))

	for i := range files {
		fileHere := files[i]

		nameHere := fileHere.Name()
		fullPath := fmt.Sprintf("%s/%s", folder, nameHere)

		lo.Must0(os.Remove(fullPath))
	}
}

func setupLogging() {
	f := lo.Must1(os.OpenFile("log.log", os.O_WRONLY|os.O_CREATE, 0o600))
	logging.Log.SetOutput(f)
}

func runWithCustomConfig(hw types.Helmet, apiClient kubernetes.Interface, config_available string) {
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

func runWithDefaultConfig(hw types.Helmet) {
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
	if err := godotenv.Load(); err != nil {
		log.Infof("Env file not present")
	}
	setupLogging()
	emptyFolder(output_dir)

	data := lo.Must(io.ReadAll(os.Stdin))

	manifestList := helm.GetManifestListFromString(string(data))
	apiClient := lo.Must1(kubernetes.NewForConfig(config.GetConfigOrDie()))

	config_available := os.Getenv("CONFIG_FILE")

	hw := types.Helmet{
		Manifests:      manifestList,
		HelmetLabel:    dependencyLabelKey,
		ManifestString: string(data),
	}
	if len(config_available) == 0 {
		runWithDefaultConfig(hw)
	} else {
		runWithCustomConfig(hw, apiClient, config_available)
	}
}
