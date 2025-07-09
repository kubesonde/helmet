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
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/samber/lo"
	logf "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"helmet.io/pkg/errors"
	"helmet.io/pkg/helm"
	"helmet.io/pkg/outbound"
	"helmet.io/pkg/pods"
	"helmet.io/pkg/types"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

func init() {
	logf.SetFormatter(&logf.TextFormatter{
		DisableColors:   true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339Nano,
	})
}

var (
	log = logf.WithFields(logf.Fields{
		"package": "core",
	})
	HelmetPodLabel = "helmet.io/chart"
)

/**
FIXMEs:
- remove empty yaml files.
	- Example:
	==> airbyte_charts_airbyte-bootloader_templates_bootloader-secrets.yaml <==
		{}
	Content is empty because .Values.secrets is empty in the main chart
- Check cases where there is no chart name

*/

type ChartStats struct {
	Dependencies []string         `json:"dependencies"`
	Services     map[string]int   `json:"services"`
	Error        errors.HelmError `json:"error,omitempty"`
}

type Retval struct {
	Key   string
	Value helm.HelmManifest
}

func WriteManifestList(manifestList helm.HelmManifestList, output_dir string) error {
	for key := range manifestList {
		data := lo.Must1(yaml.Marshal(manifestList[key]))

		pathName := strings.ReplaceAll(key, "/", helm.FILE_SEPARATOR)

		path := fmt.Sprintf("%s/%s", output_dir, pathName)
		err2 := os.WriteFile(path, data, 0o600)
		if err2 != nil {
			return err2
		}
	}
	return nil
}

func WriteToList(data []byte, filename string, output_dir string) {
	path := fmt.Sprintf("%s/%s", output_dir, filename)
	lo.Must0(os.WriteFile(path, data, 0o600))
}

/*
This function is the core of network policy building. It contains the logic to create policies.
Signature of the generated function includes:
  - policyName: usually is the name of the dependency
  - egress_dependencies: list of descendants of the dependency (access is required to those)
  - own_manifests: list of manifests of the given dependency
  - ingress_dependencies: list of ancestors of the dependency (access should be allowed)
  - isMainChart: boolean flag to signal the presence of the main chart
*/
func prepareNetworkPolicy(_k8sapiIP string, _kubernetesPort int32) func(policyName string, egress_dependencies map[string]helm.HelmManifestList, own_manifest map[string]helm.HelmManifestList, ingress_dependencies map[string]helm.HelmManifestList, isMainChart bool) string {
	return func(policyName string, egress_dependencies map[string]helm.HelmManifestList, own_manifest map[string]helm.HelmManifestList, ingress_dependencies map[string]helm.HelmManifestList, isMainChart bool) string {
		eDependencyLabelList := lo.Keys(egress_dependencies)

		_, polFound := lo.Find(eDependencyLabelList, func(depLabel string) bool {
			return depLabel == policyName
		})
		if !polFound {
			eDependencyLabelList = append(eDependencyLabelList, policyName)
			egress_dependencies[policyName] = helm.HelmManifestList{}
		}
		labelSelector := v1.LabelSelector{
			MatchLabels: make(map[string]string),
		}
		egress := lo.FlatMap(eDependencyLabelList, func(dependencyName string, index int) []netv1.NetworkPolicyEgressRule {
			if strings.Compare(policyName, dependencyName) != 0 {
				rules := []netv1.NetworkPolicyEgressRule{}
				svcs := outbound.GetServices(egress_dependencies[dependencyName])
				compute_units := pods.GetComputeUnits(egress_dependencies[dependencyName])
				for _, value := range svcs {
					var svc corev1.Service
					bytes, err := yaml.Marshal(value)
					if err != nil {
						log.Error("Cannot unmarshal Service")
					}
					err = yaml.Unmarshal(bytes, &svc)
					if err != nil {
						log.Error("Cannot unmarshal Service")
					}
					labels := svc.Spec.Selector
					if labels == nil {
						labels = map[string]string{}
					}
					labels[HelmetPodLabel] = dependencyName
					ports_to_use := ComputeServicePortForGivenService(value, compute_units)
					if len(ports_to_use) > 0 {
						rules = append(rules, netv1.NetworkPolicyEgressRule{
							To: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &v1.LabelSelector{
										MatchLabels: labels,
									},
								},
							},

							Ports: ports_to_use,
						})
					}
				}
				return rules
			} else {
				return []netv1.NetworkPolicyEgressRule{{
					To: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &v1.LabelSelector{
								MatchLabels: map[string]string{HelmetPodLabel: dependencyName},
							},
						},
					},

					Ports: nil,
				}}
			}
		})

		portIngress := BuildIngressNetworkPolicyForExternalComponents(own_manifest[policyName])
		var ingress []netv1.NetworkPolicyIngressRule
		log.Info(fmt.Sprintf("PortIngress: %v -- mainchart %v", portIngress, isMainChart))
		if len(portIngress) > 0 {
			if isMainChart {
				ingress = []netv1.NetworkPolicyIngressRule{
					{
						From: []netv1.NetworkPolicyPeer{
							{
								PodSelector: &v1.LabelSelector{},
							},
						},
						Ports: portIngress,
					},
				}
			} else {
				iDependencyLabelList := lo.Keys(ingress_dependencies)
				ingress = lo.Map(iDependencyLabelList, func(dependencyName string, index int) netv1.NetworkPolicyIngressRule {
					return netv1.NetworkPolicyIngressRule{
						From: []netv1.NetworkPolicyPeer{
							{
								PodSelector: &v1.LabelSelector{
									MatchLabels: map[string]string{HelmetPodLabel: dependencyName},
								},
							},
						},
						Ports: portIngress,
					}
				})
			}
		} else {
			ingress = []netv1.NetworkPolicyIngressRule{}
		}

		own_ingress := netv1.NetworkPolicyIngressRule{
			From: []netv1.NetworkPolicyPeer{
				{
					PodSelector: &v1.LabelSelector{
						MatchLabels: map[string]string{HelmetPodLabel: policyName},
					},
				},
			},
		}

		ingress = append(ingress, own_ingress)

		labelSelector = *v1.AddLabelToSelector(&labelSelector, HelmetPodLabel, policyName)

		network_policy := pods.BuildNetworkPolicyForPods(labelSelector,
			policyName,
			egress,
			ingress)

		return network_policy
	}
}

func GetKubernetesIPAndPort(client kubernetes.Interface) (string, int32) {
	endpoint := lo.Must1(client.CoreV1().Endpoints("default").Get(context.TODO(), "kubernetes", v1.GetOptions{}))
	return endpoint.Subsets[0].Addresses[0].IP, endpoint.Subsets[0].Ports[0].Port
}

/*
Method that outputs the labels of the dependencies below in the dep tree. Ancestor: a node reachable by repeated proceeding from child to parent.
Given the tree structure, it outputs all the labels that starts with the current name as a prefix.
The exact match is excluded (a chart does not dependen on itself).
*/
func FilterDependencyAncestor(dependencyNameList []string, currentName string) []string {
	var ancestors []string

	for _, depName := range dependencyNameList {
		if strings.Compare(currentName, depName) != 0 && strings.HasPrefix(currentName, depName) {
			ancestors = append(ancestors, depName)
		}
	}
	return ancestors
}

/*
Method that outputs the labels of the dependencies above in the dep tree. Descendant : a node reachable by repeated proceeding from parent to child.
Given the tree structure, it outputs all the labels that starts with the current name as a prefix.
The exact match is excluded (a chart does not dependen on itself).
*/
func FilterDependencyDescendant(dependencyNameList []string, currentName string) []string {
	var descendants []string

	for _, depName := range dependencyNameList {
		if strings.HasPrefix(depName, currentName) {
			descendants = append(descendants, depName)
		}
	}
	return descendants
}

func DependencyDescendantList(dependencies map[string]helm.HelmManifestList, currentName string) map[string]helm.HelmManifestList {
	return lo.PickByKeys(dependencies, FilterDependencyDescendant(lo.Keys(dependencies), currentName))
}

func DependencyAncestorList(dependencies map[string]helm.HelmManifestList, currentName string) map[string]helm.HelmManifestList {
	return lo.PickByKeys(dependencies, FilterDependencyAncestor(lo.Keys(dependencies), currentName))
}

/*
Compute network policies for each dependency
This function takes as input the list of resources grouped by dependency name and a function used to build policies
Returns: an array of tuples where each member has a dependency name and a network policy as map.
*/
func computeNetworkPoliciesForDependencies(
	groupedManifests map[string]helm.HelmManifestList,
	policyBuilder func(key string, egress_dependencies map[string]helm.HelmManifestList, own_manifest map[string]helm.HelmManifestList, ingress_dependencies map[string]helm.HelmManifestList, isMainChart bool) string,
) []Retval {
	depNameList := lo.Keys(groupedManifests)
	depsNetpol := lo.Map(depNameList, func(key string, _ int) Retval {
		depDescendantList := DependencyDescendantList(groupedManifests, key)

		depAncestorList := DependencyAncestorList(groupedManifests, key)
		pods.AddWrapperLabelToPods(groupedManifests[key], HelmetPodLabel)
		netpol := policyBuilder(key, depDescendantList, groupedManifests, depAncestorList, false)

		log.WithFields(logf.Fields{
			"dependency": key,
			"descendant": lo.Keys(depDescendantList),
			"ancestors":  lo.Keys(depAncestorList),
		}).Info("DependencyInfo")
		var helmW helm.HelmManifest
		lo.Must0(yaml.Unmarshal([]byte(netpol), &helmW))
		return Retval{fmt.Sprintf("%s--netpol.yaml", key), helmW}
	})
	return depsNetpol
}

func addlabelstopods(groupedManifests map[string]helm.HelmManifestList) {
	depNameList := lo.Keys(groupedManifests)
	lo.ForEach(depNameList, func(key string, _ int) {
		pods.AddWrapperLabelToPods(groupedManifests[key], HelmetPodLabel)
	})
}

/*
This HoF returns a function to build policies. We need this artifact to store the information about kubernetes IP and port.
*/
func setupNetworkPolicyBuilder(client kubernetes.Interface) func(key string, egress_dependencies map[string]helm.HelmManifestList, own_manifest map[string]helm.HelmManifestList, ingress_dependencies map[string]helm.HelmManifestList, isMainChart bool) string {
	kubernetesIP, kubernetesPort := GetKubernetesIPAndPort(client)
	return prepareNetworkPolicy(kubernetesIP, kubernetesPort)
}

func GetNamespace(list types.Helmet) string {
	ns := pods.GetNamespace(list.Manifests)
	namespace := "default"
	nameService := ns
	if nameService != "" {
		namespace = nameService
	}
	return namespace
}

func ComputeServicePortForGivenService(service helm.HelmManifest, compute_units helm.HelmManifestList) []netv1.NetworkPolicyPort {
	network_policy_ports := []netv1.NetworkPolicyPort{}

	svcManifests := helm.HelmManifestList{}
	svcManifests["test"] = service
	servicePorts := outbound.ManifestToIngressNetPolPortDebug(svcManifests)

	var svc corev1.Service
	svc_bytes, _ := yaml.Marshal(service)
	lo.Must0(yaml.Unmarshal(svc_bytes, &svc))
	selector_string := lo.Must(yaml.Marshal(svc.Spec.Selector))
	selector_array := strings.Split(string(selector_string), "\n")

	applicable_units := helm.HelmManifestList{}
	for key, manifest := range compute_units {
		manifest_bytes, _ := yaml.Marshal(manifest)
		manifest_string := string(manifest_bytes)
		if lo.EveryBy(selector_array, func(unit string) bool {
			return strings.Contains(manifest_string, unit)
		}) {
			applicable_units[key] = manifest
		}
	}
	container_ports := outbound.ManifestToComputeUnitPortsDebug(applicable_units)

	for _, service_port := range servicePorts {
		defaultProto := corev1.ProtocolTCP
		switch service_port.Protocol {
		case corev1.ProtocolUDP:
			defaultProto = service_port.Protocol
		case corev1.ProtocolSCTP:
			defaultProto = service_port.Protocol
		default:
			defaultProto = corev1.ProtocolTCP
		}

		svc_port := intstr.FromInt(int(service_port.Port))
		network_policy_ports = append(network_policy_ports, netv1.NetworkPolicyPort{
			Port:     &svc_port,
			Protocol: &defaultProto,
		})
		lo.Must(json.Marshal(service_port))

		if service_port.TargetPort.Type == intstr.String {
			port_str := service_port.TargetPort.StrVal
			for _, container_port := range container_ports {
				log.Info("Container port ", container_port)
				if strings.EqualFold(port_str, container_port.Name) {
					cont_port := intstr.FromInt(int(container_port.ContainerPort))
					network_policy_ports = append(network_policy_ports, netv1.NetworkPolicyPort{
						Port:     &cont_port,
						Protocol: &defaultProto,
					})
				}
			}
		} else if service_port.TargetPort.Type == intstr.Int && service_port.TargetPort.IntVal != 0 {
			network_policy_ports = append(network_policy_ports, netv1.NetworkPolicyPort{
				Port:     &service_port.TargetPort,
				Protocol: &defaultProto,
			})
		}
	}

	return lo.Uniq(network_policy_ports)
}

func BuildIngressNetworkPolicyForExternalComponents(dependency_manifests helm.HelmManifestList) []netv1.NetworkPolicyPort {
	services := outbound.GetServices(dependency_manifests)
	compute_units := pods.GetComputeUnits(dependency_manifests)
	network_policy_ports := []netv1.NetworkPolicyPort{}
	for _, service := range services {
		svc_netpol_ports := ComputeServicePortForGivenService(service, compute_units)
		network_policy_ports = append(network_policy_ports, svc_netpol_ports...)
	}
	return network_policy_ports
}

/*
This function prints to the log information regarding service labels and pod labels
which are used to recognize which pods a service refers to.
*/
func ComputePortInformation(groupedManifests map[string]helm.HelmManifestList) {
	for dependency, manifests := range groupedManifests {
		services := outbound.GetServices(manifests)
		for _, service := range services {
			var svc corev1.Service
			svc_bytes, _ := yaml.Marshal(service)
			lo.Must0(yaml.Unmarshal(svc_bytes, &svc))
			selector_string := lo.Must(yaml.Marshal(svc.Spec.Selector))
			selector_array := strings.Split(string(selector_string), "\n")
			compute_units := pods.GetComputeUnits(manifests)

			applicable_units := helm.HelmManifestList{}
			for key, manifest := range compute_units {
				manifest_bytes, _ := yaml.Marshal(manifest)
				manifest_string := string(manifest_bytes)
				if lo.EveryBy(selector_array, func(unit string) bool {
					return strings.Contains(manifest_string, unit)
				}) {
					applicable_units[key] = manifest
				}
			}
			container_ports := outbound.ManifestToComputeUnitPortsDebug(applicable_units)
			json_ports_compute, _ := json.Marshal(container_ports)
			svcManifests := helm.HelmManifestList{}
			svcManifests["test"] = service
			json_ports_svc, _ := json.Marshal(outbound.ManifestToIngressNetPolPortDebug(svcManifests))

			var servicename interface{}
			v, ok := service["metadata"].(helm.HelmManifest)
			if ok {
				servicename = v["name"]
			} else {
				servicename = service["metadata"].(map[string]interface{})["name"]
			}

			log.WithFields(logf.Fields{
				"dependency": dependency, "selector": selector_array,
				"service": servicename, "computeUnits": outbound.GetComputeUnitsNames(applicable_units), "containerPorts": string(json_ports_compute), "servicePorts": string(json_ports_svc),
			}).Info("ComputePortInformation")

			cu_labels := outbound.GetComputeUnitsLabels(applicable_units)

			log.WithFields(logf.Fields{
				"dependency": dependency,
				"service":    servicename, "serviceSelector": string(lo.Must1(json.Marshal(selector_array))), "cuName": string(lo.Must1(json.Marshal(cu_labels))),
			}).Info("ServiceInformation")
		}
	}
}

func SecureWholeChartFromList(Helmet types.Helmet, client kubernetes.Interface, output_dir string) (helm.HelmManifestList, map[string][]string, map[string][]string, error) {
	stats := ChartStats{}

	policyBuilder := setupNetworkPolicyBuilder(client)
	groupedManifests := helm.GroupManifestsByDependency(Helmet.Manifests)
	log.WithFields(logf.Fields{"TotalDependencies": len(groupedManifests)}).Info("STATS")
	if len(groupedManifests) == 0 {
		log.Error("Chart is empty. Cannot process data")
		return Helmet.Manifests, nil, nil, nil
	}

	chartName := helm.GetChartName(groupedManifests)
	dependencies := lo.OmitByKeys(groupedManifests, []string{chartName})
	template := groupedManifests[chartName]
	depTree := map[string][]string{}
	ancestors := map[string][]string{}
	for _, dep := range lo.Keys(groupedManifests) {
		depTree[dep] = lo.Filter(lo.Keys(DependencyDescendantList(groupedManifests, dep)), func(val string, _ int) bool { return val != dep })
		ancestors[dep] = lo.Keys(DependencyAncestorList(groupedManifests, dep))
	}
	log.Infof("Dep Tree: %v", depTree)
	log.Infof("Ancestors: %v", ancestors)
	stats.Dependencies = lo.Keys(groupedManifests)

	ComputePortInformation(groupedManifests)
	depsNetpol := computeNetworkPoliciesForDependencies(groupedManifests, policyBuilder)

	stats.Services = outbound.AddLabelToDependencyServices(dependencies, Helmet.HelmetLabel)

	if stats.Services[chartName] == 0 {
		log.WithFields(logf.Fields{"chart": chartName}).Warnf("No service found")
	} else {
		log.WithFields(logf.Fields{"chart": chartName}).Infof("Found %d service", stats.Services[chartName])
	}
	for dep, depManifestList := range groupedManifests {
		netPols := outbound.GetObjects(depManifestList, "NetworkPolicy")
		log.WithFields(logf.Fields{"TotalNetPolPerDep": len(netPols), "dependency": dep}).Info("STATS")
		if !helm.ValidateMisconfigurationsInChart(depManifestList, false) {
			log.WithFields(logf.Fields{"Misconfig": "HostNetwork", "dependency": dep}).Info("STATS")
		}
	}

	template, _ = outbound.AddLabelToServices(template, Helmet.HelmetLabel, chartName)

	pods.AddWrapperLabelToPods(template, HelmetPodLabel)

	netpol := policyBuilder(chartName, dependencies, map[string]helm.HelmManifestList{chartName: template}, map[string]helm.HelmManifestList{}, true)
	var mainNetpol helm.HelmManifest
	err := yaml.Unmarshal([]byte(netpol), &mainNetpol)
	if err != nil {
		return nil, nil, nil, err
	}

	finalManifests := helm.HelmManifestList{}
	for _, manifests := range dependencies {
		finalManifests = lo.Assign(finalManifests, manifests)
	}
	for _, item := range depsNetpol {
		finalManifests[item.Key] = item.Value
	}
	finalManifests[fmt.Sprintf("%s--netpol.yaml", chartName)] = mainNetpol

	finalManifests = lo.Assign(finalManifests, template)

	return finalManifests, depTree, ancestors, nil
}

func AddCustomLabelsToChart(Helmet types.Helmet, client kubernetes.Interface, output_dir string) (helm.HelmManifestList, error) {
	stats := ChartStats{}

	groupedManifests := helm.GroupManifestsByDependency(Helmet.Manifests)
	log.WithFields(logf.Fields{"TotalDependencies": len(groupedManifests)}).Info("STATS")

	chartName := helm.GetChartName(groupedManifests)
	dependencies := lo.OmitByKeys(groupedManifests, []string{chartName})
	template := groupedManifests[chartName]

	stats.Dependencies = lo.Keys(groupedManifests)

	ComputePortInformation(groupedManifests)
	addlabelstopods(groupedManifests)

	stats.Services = outbound.AddLabelToDependencyServices(dependencies, Helmet.HelmetLabel)

	if stats.Services[chartName] == 0 {
		log.WithFields(logf.Fields{"chart": chartName}).Warnf("No service found")
	} else {
		log.WithFields(logf.Fields{"chart": chartName}).Infof("Found %d service", stats.Services[chartName])
	}

	for dep, depManifestList := range groupedManifests {
		netPols := outbound.GetObjects(depManifestList, "NetworkPolicy")
		log.WithFields(logf.Fields{"TotalNetPolPerDep": len(netPols), "dependency": dep}).Info("STATS")
		if !helm.ValidateMisconfigurationsInChart(depManifestList, false) {
			log.WithFields(logf.Fields{"Misconfig": "HostNetwork", "dependency": dep}).Info("STATS")
		}
	}

	template, _ = outbound.AddLabelToServices(template, Helmet.HelmetLabel, chartName)
	pods.AddWrapperLabelToPods(template, HelmetPodLabel)

	finalManifests := helm.HelmManifestList{}
	for _, manifests := range dependencies {
		finalManifests = lo.Assign(finalManifests, manifests)
	}

	finalManifests = lo.Assign(finalManifests, template)

	return finalManifests, nil
}
