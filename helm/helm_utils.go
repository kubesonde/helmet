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

package helm

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	"crypto/sha1"
	"encoding/base64"

	"github.com/samber/lo"
	logf "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helmet.io/pkg/errors"
	"helmet.io/pkg/logging"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	yaml4 "sigs.k8s.io/yaml"
)

var (
	FILE_SEPARATOR          = "_"
	MANIFEST_SEPARATOR      = "\n---\n"
	MANIFEST_SEPARATOR_ZERO = "---\n#"
	log                     = logging.LOGGER.WithFields(logf.Fields{
		"package": "helm_utils",
	})
)

type HelmManifest map[string]interface{}
type HelmManifestList map[string]HelmManifest

func getActionConfig(namespace string) (*action.Configuration, error) {
	actionConfig := new(action.Configuration)
	var kubeConfig *genericclioptions.ConfigFlags

	config := lo.Must1(config.GetConfig())

	kubeConfig = genericclioptions.NewConfigFlags(false)
	kubeConfig.APIServer = &config.Host
	kubeConfig.BearerToken = &config.BearerToken
	kubeConfig.CAFile = &config.CAFile
	kubeConfig.Namespace = &namespace
	if err := actionConfig.Init(kubeConfig, namespace, os.Getenv("HELM_DRIVER"), log.Printf); err != nil {
		log.Error("Could not find a running Kubenetes instance")
		return nil, err
	}
	return actionConfig, nil
}

/*
This function return a string containing all the generated k8s manifests
*/
func getManifest(namespace string, chart string, releaseName string, settings *cli.EnvSettings) (string, error) {

	actionConfig := lo.Must1(getActionConfig(namespace))
	client := action.NewInstall(actionConfig)
	client.ReleaseName = releaseName
	client.Namespace = namespace
	client.DryRun = true
	client.Replace = true
	client.IncludeCRDs = true
	cp, err := client.LocateChart(chart, settings)
	if err == nil {
		log.WithFields(logf.Fields{
			"namespace": namespace,
			"chart":     chart,
		}).Info("Chart was found")
	} else {
		log.WithFields(logf.Fields{
			"namespace": namespace,
			"chart":     chart,
			"error":     errors.StringToError(err.Error()),
		}).Error("Chart was not found")
		return "", err
	}
	chartReq, err := loader.Load(cp)
	if err == nil {
		log.WithFields(logf.Fields{
			"namespace": namespace,
			"chart":     chart,
		}).Info("Chart was loaded")
	} else {
		log.WithFields(logf.Fields{
			"namespace": namespace,
			"chart":     chart,
			"error":     err.Error(),
		}).Error("Chart could not be loaded")
		return "", err
	}
	release, err := client.Run(chartReq, chartReq.Values)
	if err != nil {
		log.WithFields(logf.Fields{
			"namespace": namespace,
			"chart":     chart,
			"error":     errors.StringToError(err.Error()),
		}).Error("Chart could not be installed")
		return "", err
	}
	return release.Manifest, err
}

func splitRenderedResources(manifest string) []string {

	if strings.HasPrefix(manifest, "--") {
		manifest = "\n" + manifest
	}

	manifestSplit := strings.Split(manifest, MANIFEST_SEPARATOR_ZERO)

	for i := range manifestSplit {
		manifestSplit[i] = fmt.Sprintf("#%s", manifestSplit[i])
	}

	return lo.Filter(manifestSplit, func(text string, index int) bool {
		lines := strings.Split(text, "\n")
		line := lines[0]
		t := strings.TrimSpace(line)

		if t == "" || strings.HasPrefix(t, "--") {
			return false
		}

		if lo.EveryBy(lines, func(item string) bool {
			return strings.HasPrefix(item, "#") || len(item) == 0
		}) {
			return false
		}

		if len(lines) < 4 {

			return false
		}

		return true
	})
}

func isFileName(targetLine string) bool {
	return strings.Contains(targetLine, "# Source:") && (strings.HasSuffix(targetLine, ".yaml") || strings.HasSuffix(targetLine, ".yml"))
}

func computeFilenameForResource(releaseName string, manifestYaml HelmManifest) string {
	var template_path string
	log.WithFields(logf.Fields{
		"Name Prob": manifestYaml,
	}).Warn("File does not have a name.")

	if manifestYaml["metadata"] == nil {
		if manifestYaml["name"] == nil {
			template_path = fmt.Sprintf("%s-unknown.yaml", releaseName)
		} else {
			template_path = fmt.Sprintf("%s-unknown.yaml", manifestYaml["name"])
		}
	} else {
		if manifestYaml["metadata"].(HelmManifest)["name"] == nil {
			template_path = fmt.Sprintf("%s-unknown.yaml", releaseName)
		} else {
			template_path = fmt.Sprintf("%s-unknown.yaml", manifestYaml["metadata"].(HelmManifest)["name"])
		}
	}
	return template_path
}

func getResourcesWithName(releaseName string, resources []string) HelmManifestList {
	var manifestList = make(HelmManifestList)

	lo.ForEach(resources, func(item string, index int) {
		itemSplit := strings.Split(item, "\n")
		manifestYaml := make(HelmManifest)
		err := yaml.Unmarshal([]byte(item), manifestYaml)
		var targetLine string

		if len(itemSplit) > 1 {
			if len(itemSplit[0]) < 2 {
				targetLine = itemSplit[1]
			} else {
				targetLine = itemSplit[0]
			}
			targetLine = strings.Trim(targetLine, " ")
			var template_path string
			if isFileName(targetLine) {
				template_path = targetLine[10:]
			} else {
				template_path = computeFilenameForResource(releaseName, manifestYaml)

				log.WithFields(logf.Fields{
					"releaseName":  releaseName,
					"assignedName": template_path}).Warn("File does not have a name.")
			}
			if err != nil {
				log.WithFields(logf.Fields{
					"releaseName":  releaseName,
					"assignedName": template_path,
					"error":        errors.TemplateToYamlError}).
					Errorf(err.Error())
				return
			} else {
				if lo.IndexOf(lo.Keys(manifestList), template_path) != -1 {
					hasher := sha1.New()
					hasher.Write([]byte(item))
					sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
					manifestList[template_path+sha+".yaml"] = manifestYaml
				} else {
					manifestList[template_path] = manifestYaml
				}
			}
		}
	})
	return manifestList
}

func storeChartsLocally(settings *cli.EnvSettings, chartName string, releaseName string) (HelmManifestList, error) {
	manifest, err := getManifest(settings.Namespace(), chartName, releaseName, settings)
	if err != nil {
		return nil, err
	}
	manifestSplit := splitRenderedResources(manifest)
	return getResourcesWithName(releaseName, manifestSplit), nil
}

func GetManifestsFromLocalFolderAsString(folderPath string) string {
	filePath := folderPath + "/%s"
	files := lo.Must1(os.ReadDir(folderPath))

	fileList := lo.Reduce(files, func(agg []string, item fs.DirEntry, index int) []string {
		return append(agg, item.Name())
	}, []string{})

	manifests := lo.Map(fileList, func(file string, index int) string {
		return string(lo.Must1(os.ReadFile(fmt.Sprintf(filePath, file))))
	})

	return lo.Reduce(manifests, func(acc string, item string, index int) string {
		return acc + MANIFEST_SEPARATOR + item
	}, "")
}

func ManifestsToString(manifests HelmManifestList) string {

	fileList := lo.Keys(manifests)

	manifest_array := lo.Map(fileList, func(file string, index int) string {
		return string(lo.Must1(yaml4.Marshal(manifests[file])))
	})

	return lo.Reduce(manifest_array, func(acc string, item string, index int) string {
		return acc + MANIFEST_SEPARATOR + item
	}, "")

}

func readChartsFromLocalFolder(folderPath string) (HelmManifestList, error) {
	filePath := folderPath + "/%s"
	var manifestList = make(HelmManifestList)
	files := lo.Must1(os.ReadDir(folderPath))

	fileList := lo.Reduce(files, func(agg []string, item fs.DirEntry, index int) []string {
		return append(agg, item.Name())
	}, []string{})
	manifestYaml := make(map[string]interface{})

	for _, item := range fileList {

		yfile := lo.Must1(os.ReadFile(fmt.Sprintf(filePath, item)))
		err := yaml.Unmarshal(yfile, manifestYaml)
		if err != nil {
			return manifestList, err
		}
		manifestList[strings.ReplaceAll(item, FILE_SEPARATOR, "/")] = manifestYaml
	}
	return manifestList, nil
}

/*
This function returns a map of the generated k8s manifests
*/
func GetManifestList(settings *cli.EnvSettings, chartName string, releaseName string, forceLoad bool, folderName string) (HelmManifestList, error) {
	folderPath := fmt.Sprintf("./%s/", folderName)
	_, err := os.Stat(folderPath)
	if !forceLoad && err == nil {
		log.WithFields(logf.Fields{
			"chart":       chartName,
			"releaseName": releaseName,
		}).Infof("Reading charts from local folder")
		return readChartsFromLocalFolder(folderPath)
	} else {
		if err != nil {
			lo.Must0(os.Mkdir(folderName, 0750))
		}
		log.WithFields(logf.Fields{
			"chart":       chartName,
			"releaseName": releaseName,
		}).Infof("Fetching chart from source")
		chart, err := storeChartsLocally(settings, chartName, releaseName)
		ValidateMisconfigurationsInChart(chart, true)
		return chart, err
	}
}

/*
*
This function returns `true` if the chart is correctly configured, else `false`
*/
func ValidateMisconfigurationsInChart(chart HelmManifestList, printError bool) bool {
	hostNetworkTrue := lo.Must1(regexp.Compile("\"hostNetwork\"[ ]*:[ ]*true"))
	for _, key := range lo.Keys(chart) {
		content := lo.Must1(json.Marshal(chart[key]))
		if hostNetworkTrue.MatchString(string(content)) {
			if printError {
				fmt.Fprintf(os.Stderr, "\n\033[91mMisconfiguration found in chart: \n%s\nThe hostNetwork flag is set to True, so the applied policies will not have any effect.\nSet it to false to resolve the error.\n\n\033[0m", key)
			}

			return false
		}
	}
	return true
}

func GetManifestListFromString(manifest string) HelmManifestList {
	return getResourcesWithName("release", splitRenderedResources(manifest))
}

func GetChartDependencyTreePath(manifestPath string) []string {

	var rgx = regexp.MustCompile(`^([^/]*)|/charts/([^/]*)`)
	rs := rgx.FindAllStringSubmatch(manifestPath, -1)
	return lo.Map(rs, func(x []string, index int) string {

		if x[1] != "" {
			return x[1]
		} else {
			return x[2]
		}
	})
}

func GetDependencyLabel(manifestPath string) string {
	return strings.Join(GetChartDependencyTreePath(manifestPath), FILE_SEPARATOR)
}

func GetChartName(groupedManifests map[string]HelmManifestList) string {
	var rgx = regexp.MustCompile(`^([^_]*)`)
	return rgx.FindString(lo.Keys(groupedManifests)[0])
}

func GroupManifestsByDependency(manifests HelmManifestList) map[string]HelmManifestList {
	manifestKeys := lo.Keys(manifests)
	var manifestList = make(map[string]HelmManifestList)
	groupedManifests := lo.Reduce(manifestKeys, func(acc map[string]HelmManifestList, manifestKey string, index int) map[string]HelmManifestList {
		tree := strings.Split(manifestKey, "/")
		dependencyLabel := GetDependencyLabel(manifestKey)

		isCRD := strings.Contains(tree[0], "crds")
		if !isCRD {

			_, ok := acc[dependencyLabel]
			if !ok {
				acc[dependencyLabel] = make(HelmManifestList, 0)
			}
			acc[dependencyLabel][manifestKey] = manifests[manifestKey]
		} else {
			log.WithFields(logf.Fields{"chart": tree[0]}).Warnf("CRD %s", tree)
		}
		return acc
	}, manifestList)
	return groupedManifests
}

/*
Load chart
*/
func GetValuesFromChart(namespace string, releaseName string, settings *cli.EnvSettings) (map[string]interface{}, error) {

	actionConfig := new(action.Configuration)
	client := action.NewInstall(actionConfig)

	client.Namespace = namespace
	client.ReleaseName = releaseName

	cp, err := client.LocateChart(releaseName, settings)

	if err != nil {
		log.WithField("chart", releaseName).Errorf("Chart %s not found", releaseName)
	} else {
		log.
			WithFields(logf.Fields{"chart": releaseName,
				"name": cp[strings.LastIndex(cp, ",")+1:]}).
			Infof("Chart %s found", releaseName)
		chartReq, err := loader.Load(cp)
		if err != nil {
			log.Errorf("Error loading chart %s", releaseName)
		} else {
			values := chartReq.Values
			return values, nil
		}
	}
	return nil, err
}

/*
Load chart and get templates
*/
func GetTemplatesFromChart(namespace string, releaseName string, settings *cli.EnvSettings) ([]*chart.File, error) {

	actionConfig := new(action.Configuration)
	client := action.NewInstall(actionConfig)

	client.Namespace = namespace
	client.ReleaseName = releaseName

	cp, err := client.LocateChart(releaseName, settings)

	if err != nil {
		log.WithField("chart", releaseName).Errorf("Chart %s not found", releaseName)
	} else {
		log.
			WithFields(logf.Fields{"chart": releaseName,
				"name": cp[strings.LastIndex(cp, ",")+1:]}).
			Infof("Chart %s found", releaseName)
		chartReq, err := loader.Load(cp)
		if err != nil {
			log.Errorf("Error loading chart %s", releaseName)
		} else {
			values := chartReq.Templates
			return values, nil
		}
	}
	return nil, err
}
func SortNetPolPorts(netPolPorts []netv1.NetworkPolicyPort) []netv1.NetworkPolicyPort {

	sort.Slice(netPolPorts, func(i, j int) bool {
		if netPolPorts[i].Port.Type == 0 {
			if netPolPorts[j].Port.Type == 0 {
				return netPolPorts[i].Port.IntVal < netPolPorts[j].Port.IntVal
			} else {
				return true
			}
		} else {
			if netPolPorts[j].Port.Type == 1 {
				return netPolPorts[i].Port.StrVal < netPolPorts[j].Port.StrVal
			} else {
				return false
			}
		}
	})
	return netPolPorts
}

func SortEgressPolicies(egressPol []netv1.NetworkPolicyEgressRule) []netv1.NetworkPolicyEgressRule {

	sort.Slice(egressPol, func(i, j int) bool {
		if egressPol[i].To[0].PodSelector != nil {
			keyI := lo.Keys(egressPol[i].To[0].PodSelector.MatchLabels)[0]
			valueI := egressPol[i].To[0].PodSelector.MatchLabels[keyI]

			if egressPol[j].To[0].PodSelector != nil {
				keyJ := lo.Keys(egressPol[j].To[0].PodSelector.MatchLabels)[0]
				valueJ := egressPol[j].To[0].PodSelector.MatchLabels[keyJ]
				return valueI < valueJ
			} else {
				return true
			}
		} else {
			return false
		}
	})
	return egressPol
}

func IsPolEmpty(polPeer []netv1.NetworkPolicyPeer) bool {
	return len(polPeer) == 0 || polPeer[0].PodSelector == nil || polPeer[0].PodSelector.MatchLabels == nil || len(polPeer[0].PodSelector.MatchLabels) == 0
}

func SortIngressPolicies(ingressPol []netv1.NetworkPolicyIngressRule) []netv1.NetworkPolicyIngressRule {
	sort.Slice(ingressPol, func(i, j int) bool {
		if !IsPolEmpty(ingressPol[i].From) {
			keyI := lo.Keys(ingressPol[i].From[0].PodSelector.MatchLabels)[0]
			valueI := ingressPol[i].From[0].PodSelector.MatchLabels[keyI]

			if !IsPolEmpty(ingressPol[j].From) {
				keyJ := lo.Keys(ingressPol[j].From[0].PodSelector.MatchLabels)[0]
				valueJ := ingressPol[j].From[0].PodSelector.MatchLabels[keyJ]
				return valueI < valueJ
			} else {
				return true
			}
		} else {
			if len(ingressPol[i].Ports) > 0 {
				valueI := ingressPol[i].Ports[0].Port.StrVal
				if len(ingressPol[j].Ports) > 0 {
					valueJ := ingressPol[j].Ports[0].Port.StrVal
					return valueI < valueJ
				} else {
					return true
				}
			} else {
				return false
			}
		}
	})
	return ingressPol
}

func ToSvc(svc string) v1.Service {
	var theService v1.Service
	err := yaml.Unmarshal([]byte(svc), &theService)
	if err != nil {
		fmt.Println(err.Error())
		return theService
	}
	return theService

}

func GetNameSpaceFromService(svc HelmManifest) string {
	metadata := svc["metadata"]
	if metadata != nil {
		if _, ok := metadata.(HelmManifest); ok {
			nameSpace := metadata.(HelmManifest)["namespace"]
			if nameSpace != nil {
				return nameSpace.(string)
			}
		} else {
			nameSpace := metadata.(map[string]interface{})["namespace"]
			if nameSpace != nil {
				return nameSpace.(string)
			}
		}
	}
	return ""
}

func GetValueFromManifest(manifest HelmManifest, labelList []string) interface{} {
	aux_manifest := manifest
	for _, label := range labelList[:len(labelList)-1] {
		element, ok := aux_manifest[label]
		if ok {
			elementHelmManifest, elementIsHelmManifest := element.(HelmManifest)
			if elementIsHelmManifest {
				aux_manifest = elementHelmManifest
			} else {
				elementMapInterface, elementIsMapInterface := element.(map[string]interface{})
				if elementIsMapInterface {
					aux_manifest = elementMapInterface
				} else {
					log.Error("Element is not helmManifest or map interface")
					return ""
				}
			}
		}
	}

	return aux_manifest[labelList[len(labelList)-1]]
}
