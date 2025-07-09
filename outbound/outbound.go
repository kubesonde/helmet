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

package outbound

import (
	"encoding/json"
	"strings"

	"github.com/samber/lo"
	logf "github.com/sirupsen/logrus"
	"helmet.io/pkg/helm"
	"helmet.io/pkg/pods"
	types "helmet.io/pkg/types"
	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

var (
	log = logf.WithFields(logf.Fields{
		"package": "outbound",
	})

	_COMPUTE_UNITS_DETAILS = map[string]interface{}{
		"Pod": func(manifest helm.HelmManifest) (string, map[string]string, []v1.Container, []v1.Volume, string, error) {
			var aux_pod v1.Pod
			aux_cu, err := loadObject[v1.Pod](manifest, aux_pod)
			return aux_cu.Name, aux_cu.Labels, append(aux_cu.Spec.Containers, aux_cu.Spec.InitContainers...), aux_cu.Spec.Volumes, aux_cu.Namespace, err
		},
		"Job": func(manifest helm.HelmManifest) (string, map[string]string, []v1.Container, []v1.Volume, string, error) {
			var aux_pod batchv1.Job
			aux_cu, err := loadObject[batchv1.Job](manifest, aux_pod)
			return aux_cu.Name, aux_cu.Spec.Template.Labels, append(aux_cu.Spec.Template.Spec.Containers, aux_cu.Spec.Template.Spec.InitContainers...), aux_cu.Spec.Template.Spec.Volumes, aux_cu.Namespace, err
		},
		"Cronjob": func(manifest helm.HelmManifest) (string, map[string]string, []v1.Container, []v1.Volume, string, error) {
			var aux_pod batchv1.CronJob
			aux_cu, err := loadObject[batchv1.CronJob](manifest, aux_pod)
			return aux_cu.Spec.JobTemplate.Name, aux_cu.Spec.JobTemplate.Labels, append(aux_cu.Spec.JobTemplate.Spec.Template.Spec.Containers, aux_cu.Spec.JobTemplate.Spec.Template.Spec.InitContainers...), aux_cu.Spec.JobTemplate.Spec.Template.Spec.Volumes, aux_cu.Namespace, err
		},
		"DaemonSet": func(manifest helm.HelmManifest) (string, map[string]string, []v1.Container, []v1.Volume, string, error) {
			var aux_pod apps.DaemonSet
			aux_cu, err := loadObject[apps.DaemonSet](manifest, aux_pod)
			return aux_cu.Name, aux_cu.Spec.Template.Labels, append(aux_cu.Spec.Template.Spec.Containers, aux_cu.Spec.Template.Spec.InitContainers...), aux_cu.Spec.Template.Spec.Volumes, aux_cu.Namespace, err
		},
		"StatefulSet": func(manifest helm.HelmManifest) (string, map[string]string, []v1.Container, []v1.Volume, string, error) {
			var aux_pod apps.StatefulSet
			aux_cu, err := loadObject[apps.StatefulSet](manifest, aux_pod)
			return aux_cu.Name, aux_cu.Spec.Template.Labels, append(aux_cu.Spec.Template.Spec.Containers, aux_cu.Spec.Template.Spec.InitContainers...), aux_cu.Spec.Template.Spec.Volumes, aux_cu.Namespace, err
		},
		"Deployment": func(manifest helm.HelmManifest) (string, map[string]string, []v1.Container, []v1.Volume, string, error) {
			var aux_pod apps.Deployment
			aux_cu, err := loadObject[apps.Deployment](manifest, aux_pod)
			return aux_cu.Name, aux_cu.Spec.Template.Labels, append(aux_cu.Spec.Template.Spec.Containers, aux_cu.Spec.Template.Spec.InitContainers...), aux_cu.Spec.Template.Spec.Volumes, aux_cu.Namespace, err
		},
	}
)

func init() {
	logf.SetFormatter(&logf.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
}

func AddLabelToDependencyServices(dependencies map[string]helm.HelmManifestList, labelKey string) map[string]int {
	service_in_deps := map[string]int{}
	new_service_manifest := make(map[string]helm.HelmManifestList)
	for name, manifestList := range dependencies {
		newManifestList, ok := AddLabelToServices(manifestList, labelKey, name)

		if ok {
			new_service_manifest[name] = newManifestList

			service_in_deps[name] += 1
		} else {
			service_in_deps[name] = 0
		}
	}

	for key, value := range new_service_manifest {
		dependencies[key] = value
	}

	return service_in_deps
}

func DependencyRelation(manifestList helm.HelmManifestList) []string {
	var result1 []string
	for key, res := range manifestList {
		value := helm.GetValueFromManifest(res, []string{"metadata", "labels", "app.kubernetes.io/part-of"})
		strValue, isStr := value.(string)
		if isStr {
			result1 = append(result1, strValue)
			log.WithFields(logf.Fields{"chart": key}).Info(value)
		}
	}
	return result1
}

func AddLabelToServices(manifestList helm.HelmManifestList, labelKey string, labelValue string) (helm.HelmManifestList, bool) {
	serviceLabel := []string{"metadata", "labels"}
	found := false
	updatedManifests := make(helm.HelmManifestList)
	for key, res := range manifestList {
		value, ok := res["kind"]
		if ok && value == "Service" {
			found = true

			updatedManifests[key] = pods.SetLabelValue(res, serviceLabel, labelKey, labelValue)
		}
	}
	for key, res := range updatedManifests {
		manifestList[key] = res
	}

	if !found {
		log.WithFields(logf.Fields{"chart": labelValue}).Warn("Could not find any service")
	}
	return manifestList, found
}

func GetObjects(manifestList helm.HelmManifestList, objectKind string) []helm.HelmManifest {
	values := lo.Values(manifestList)
	return lo.Filter(values, func(item helm.HelmManifest, index int) bool {
		return item["kind"] == objectKind
	})
}

func GetServices(manifestList helm.HelmManifestList) []helm.HelmManifest {
	return GetObjects(manifestList, "Service")
}

func GetNetworkPolicies(manifestList helm.HelmManifestList) []helm.HelmManifest {
	return GetObjects(manifestList, "NetworkPolicy")
}

func loadObject[T any](manifest helm.HelmManifest, object T) (T, error) {
	bytes, err := json.Marshal(manifest)
	if err != nil {
		return object, err
	}
	err = json.Unmarshal(bytes, &object)
	if err != nil {
		return object, err
	}
	return object, nil
}

func LoadObject[T any](manifest helm.HelmManifest, object T) (T, error) {
	return loadObject(manifest, object)
}

func getContainersFromPod(manifest helm.HelmManifest) []v1.Container {
	var aux_pod v1.Pod
	aux_pod = lo.Must1(loadObject[v1.Pod](manifest, aux_pod))
	return aux_pod.Spec.Containers
}

func getContainersFromJob(manifest helm.HelmManifest) []v1.Container {
	var aux_job batchv1.Job
	aux_job = lo.Must1(loadObject[batchv1.Job](manifest, aux_job))
	return aux_job.Spec.Template.Spec.Containers
}

func getContainersFromCronJob(manifest helm.HelmManifest) []v1.Container {
	var aux_cronjob batchv1.CronJob
	aux_cronjob = lo.Must1(loadObject[batchv1.CronJob](manifest, aux_cronjob))
	return aux_cronjob.Spec.JobTemplate.Spec.Template.Spec.Containers
}

func getContainersFromDaemonSet(manifest helm.HelmManifest) []v1.Container {
	var aux_daemon_set apps.DaemonSet
	aux_daemon_set = lo.Must1(loadObject[apps.DaemonSet](manifest, aux_daemon_set))
	return aux_daemon_set.Spec.Template.Spec.Containers
}

func getContainersFromStateFulSet(manifest helm.HelmManifest) []v1.Container {
	var aux_stateful_set apps.StatefulSet
	aux_stateful_set = lo.Must1(loadObject[apps.StatefulSet](manifest, aux_stateful_set))
	return aux_stateful_set.Spec.Template.Spec.Containers
}

func getContainersFromDeployment(manifest helm.HelmManifest) []v1.Container {
	var aux_deployment apps.Deployment
	aux_deployment = lo.Must1(loadObject[apps.Deployment](manifest, aux_deployment))
	return aux_deployment.Spec.Template.Spec.Containers
}

func GetComputeUnitsNames(manifestList helm.HelmManifestList) []string {
	PODS_CONTAINER := map[string]interface{}{
		"Pod": func(manifest helm.HelmManifest) string {
			var aux_pod v1.Pod
			return lo.Must1(loadObject[v1.Pod](manifest, aux_pod)).Name
		},
		"Job": func(manifest helm.HelmManifest) string {
			var aux_pod batchv1.Job
			return lo.Must1(loadObject[batchv1.Job](manifest, aux_pod)).Spec.Template.Name
		},
		"Cronjob": func(manifest helm.HelmManifest) string {
			var aux_pod batchv1.CronJob
			return lo.Must1(loadObject[batchv1.CronJob](manifest, aux_pod)).Spec.JobTemplate.Name
		},
		"DaemonSet": func(manifest helm.HelmManifest) string {
			var aux_pod apps.DaemonSet
			return lo.Must1(loadObject[apps.DaemonSet](manifest, aux_pod)).Name
		},
		"StatefulSet": func(manifest helm.HelmManifest) string {
			var aux_pod apps.StatefulSet
			return lo.Must1(loadObject[apps.StatefulSet](manifest, aux_pod)).Name
		},
		"Deployment": func(manifest helm.HelmManifest) string {
			var aux_pod apps.Deployment
			return lo.Must1(loadObject[apps.Deployment](manifest, aux_pod)).Name
		},
	}

	cu := []string{}
	var object []helm.HelmManifest
	var each_cu_container string
	for label, function := range PODS_CONTAINER {
		object = GetObjects(manifestList, label)

		if len(object) > 0 {
			for _, manifest := range object {
				each_cu_container = function.(func(helm.HelmManifest) string)(manifest)

				cu = append(cu, each_cu_container)
			}
		}
	}
	return cu
}

func GetComputeUnitsLabels(manifestList helm.HelmManifestList) map[string]map[string]string {
	PODS_CONTAINER := map[string]interface{}{
		"Pod": func(manifest helm.HelmManifest) (string, map[string]string) {
			var aux_pod v1.Pod
			aux_cu := lo.Must1(loadObject[v1.Pod](manifest, aux_pod))
			return aux_cu.Name, aux_cu.Labels
		},
		"Job": func(manifest helm.HelmManifest) (string, map[string]string) {
			var aux_pod batchv1.Job
			aux_cu := lo.Must1(loadObject[batchv1.Job](manifest, aux_pod))
			return aux_cu.Spec.Template.Name, aux_cu.Spec.Template.Labels
		},
		"Cronjob": func(manifest helm.HelmManifest) (string, map[string]string) {
			var aux_pod batchv1.CronJob
			aux_cu := lo.Must1(loadObject[batchv1.CronJob](manifest, aux_pod))
			return aux_cu.Spec.JobTemplate.Name, aux_cu.Spec.JobTemplate.Labels
		},
		"DaemonSet": func(manifest helm.HelmManifest) (string, map[string]string) {
			var aux_pod apps.DaemonSet
			aux_cu := lo.Must1(loadObject[apps.DaemonSet](manifest, aux_pod))
			return aux_cu.Name, aux_cu.Spec.Template.Labels
		},
		"StatefulSet": func(manifest helm.HelmManifest) (string, map[string]string) {
			var aux_pod apps.StatefulSet
			aux_cu := lo.Must1(loadObject[apps.StatefulSet](manifest, aux_pod))
			return aux_cu.Name, aux_cu.Spec.Template.Labels
		},
		"Deployment": func(manifest helm.HelmManifest) (string, map[string]string) {
			var aux_pod apps.Deployment
			aux_cu := lo.Must1(loadObject[apps.Deployment](manifest, aux_pod))
			return aux_cu.Name, aux_cu.Spec.Template.Labels
		},
	}

	cu := map[string]map[string]string{}
	var object []helm.HelmManifest
	var cu_name string
	var cu_labels map[string]string
	for label, function := range PODS_CONTAINER {
		object = GetObjects(manifestList, label)
		if len(object) > 0 {
			for _, manifest := range object {
				cu_name, cu_labels = function.(func(helm.HelmManifest) (string, map[string]string))(manifest)
				cu[cu_name] = cu_labels
			}
		}
	}
	return cu
}

func mergeContainerPorts(containers []v1.Container) []v1.ContainerPort {
	ports := lo.Map(containers, func(container v1.Container, idx int) []v1.ContainerPort {
		return container.Ports
	})
	return lo.Flatten(ports)
}

func mergeEnvVariables(containers []v1.Container) []v1.EnvVar {
	envVars := lo.Map(containers, func(container v1.Container, idx int) []v1.EnvVar {
		return container.Env
	})
	return lo.Flatten(envVars)
}

func mergeContainerArguments(containers []v1.Container) []string {
	args := lo.Map(containers, func(container v1.Container, idx int) []string {
		return container.Args
	})
	return lo.Flatten(args)
}

func mergeContainerCommands(containers []v1.Container) []string {
	args := lo.Map(containers, func(container v1.Container, idx int) []string {
		return container.Command
	})
	return lo.Flatten(args)
}

func getConfigMaps(volumes []v1.Volume) []string {
	args := lo.FilterMap(volumes, func(volume v1.Volume, idx int) (string, bool) {
		configMap := volume.ConfigMap
		if configMap == nil {
			return "", false
		}

		return configMap.Name, true
	})
	return args
}

func GetComputeUnitsDetails(manifestList helm.HelmManifestList) []types.HelmET_ComputeUnit {
	computeUnits := []types.HelmET_ComputeUnit{}
	var object []helm.HelmManifest

	configMaps := lo.Reduce(GetObjects(manifestList, "ConfigMap"), func(acc map[string]string, manifest helm.HelmManifest, idx int) map[string]string {
		var cm v1.ConfigMap

		configMap := lo.Must1(loadObject(manifest, cm))
		acc[configMap.Name] = strings.Join(lo.Values(configMap.Data), "\n")
		return acc
	}, map[string]string{})

	for label, function := range _COMPUTE_UNITS_DETAILS {
		object = GetObjects(manifestList, label)
		if len(object) > 0 {
			for _, manifest := range object {
				cu_name, cu_labels, cu_containers, cu_volumes, cu_namespace, err := function.(func(helm.HelmManifest) (string, map[string]string, []v1.Container, []v1.Volume, string, error))(manifest)
				if err != nil {
					continue
				}
				configMapNames := getConfigMaps(cu_volumes)

				targetedConfigMaps := lo.Map(configMapNames, func(name string, _ int) string {
					return configMaps[name]
				})

				computeUnits = append(computeUnits, types.HelmET_ComputeUnit{
					Name:           cu_name,
					Labels:         cu_labels,
					ContainerPorts: mergeContainerPorts(cu_containers),
					EnvVars:        mergeEnvVariables(cu_containers),
					ConfigMaps:     targetedConfigMaps,
					Arguments:      mergeContainerArguments(cu_containers),
					Commands:       mergeContainerCommands(cu_containers),
					Namespace:      cu_namespace,
				})
			}
		}
	}
	return computeUnits
}

func GetHelmetServices(manifestList helm.HelmManifestList) []types.HelmET_Service {
	svcs := GetServices(manifestList)
	helmetServices := []types.HelmET_Service{}
	for _, service := range svcs {
		var svc v1.Service
		svc_bytes, _ := json.Marshal(service)
		headless := false
		if svc.Spec.ClusterIP == v1.ClusterIPNone {
			headless = true
		}
		lo.Must0(json.Unmarshal(svc_bytes, &svc))
		helmetServices = append(helmetServices, types.HelmET_Service{
			Selector:     svc.Spec.Selector,
			Labels:       svc.Labels,
			ServicePorts: svc.Spec.Ports,
			Name:         svc.Name,
			Headless:     headless,
		})
	}
	return helmetServices
}

func GetHelmetNodes(manifestList helm.HelmManifestList) []types.HelmET_Node {
	nodes := []types.HelmET_Node{}
	helmetServices := GetHelmetServices(manifestList)
	computeUnits := GetComputeUnitsDetails(manifestList)
	for _, computeUnit := range computeUnits {
		node := types.HelmET_Node{
			Name:        computeUnit.Name,
			ComputeUnit: computeUnit,
			Services:    []types.HelmET_Service{},
		}
		for _, service := range helmetServices {
			if lo.EveryBy(lo.Entries(service.Selector), func(entry lo.Entry[string, string]) bool {
				return computeUnit.Labels[entry.Key] == entry.Value
			}) {
				node.Services = append(node.Services, service)
			}
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func GetHelmetNodesWithDependencies(manifestList helm.HelmManifestList) []types.HelmET_Node {
	nodes := []types.HelmET_Node{}
	groupedManifests := helm.GroupManifestsByDependency(manifestList)

	for dependency, manifests := range groupedManifests {
		helmetServices := GetHelmetServices(manifests)
		computeUnits := GetComputeUnitsDetails(manifests)
		for _, computeUnit := range computeUnits {
			node := types.HelmET_Node{
				Name:           computeUnit.Name,
				ComputeUnit:    computeUnit,
				Services:       []types.HelmET_Service{},
				DependencyName: dependency,
			}
			for _, service := range helmetServices {
				if lo.EveryBy(lo.Entries(service.Selector), func(entry lo.Entry[string, string]) bool {
					return computeUnit.Labels[entry.Key] == entry.Value
				}) {
					node.Services = append(node.Services, service)
				}
			}
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func GetContainers(manifestList helm.HelmManifestList) []v1.Container {
	PODS_CONTAINER := map[string]interface{}{
		"Pod":         getContainersFromPod,
		"Job":         getContainersFromJob,
		"Cronjob":     getContainersFromCronJob,
		"DaemonSet":   getContainersFromDaemonSet,
		"StatefulSet": getContainersFromStateFulSet,
		"Deployment":  getContainersFromDeployment,
	}

	cu := []v1.Container{}
	var object []helm.HelmManifest
	var each_cu_container []v1.Container
	for label, function := range PODS_CONTAINER {
		object = GetObjects(manifestList, label)

		if len(object) > 0 {
			for _, manifest := range object {
				each_cu_container = function.(func(helm.HelmManifest) []v1.Container)(manifest)

				cu = append(cu, each_cu_container...)
			}
		}
	}
	return cu
}

func getServicesPorts(manifestList helm.HelmManifestList) ([]v1.ServicePort, error) {
	svcPorts := []v1.ServicePort{}
	for _, value := range GetServices(manifestList) {
		var svc v1.Service
		bytes, err := yaml.Marshal(value)
		if err != nil {
			return nil, err
		}
		err = yaml.Unmarshal(bytes, &svc)
		if err != nil {
			return nil, err
		}
		svcPorts = append(svcPorts, svc.Spec.Ports...)
	}
	return lo.Uniq(svcPorts), nil
}

func getContainerPorts(manifestList helm.HelmManifestList) []v1.ContainerPort {
	containerPorts := []v1.ContainerPort{}

	for _, container := range GetContainers(manifestList) {
		containerPorts = append(containerPorts, container.Ports...)
	}
	return containerPorts
}

func ManifestToNetPolPort(manifestList helm.HelmManifestList) []netv1.NetworkPolicyPort {
	return ConvertServicePortsToNetworkPolicyPort(lo.Must1(getServicesPorts(manifestList)))
}

func ManifestToIngressNetPolPort(manifestList helm.HelmManifestList) []netv1.NetworkPolicyPort {
	return ConvertServicePortsToIngressNetworkPolicyPort(lo.Must1(getServicesPorts(manifestList)))
}

func ManifestToIngressNetPolPortDebug_old(manifestList helm.HelmManifestList) []netv1.NetworkPolicyPort {
	return ConvertServicePortsToIngressNetworkPolicyPortForDebug(lo.Must1(getServicesPorts(manifestList)))
}

func ManifestToIngressNetPolPortDebug(manifestList helm.HelmManifestList) []v1.ServicePort {
	return lo.Must1(getServicesPorts(manifestList))
}

func ManifestToComputeUnitPortsDebug(manifestList helm.HelmManifestList) []v1.ContainerPort {
	return lo.Uniq(getContainerPorts(manifestList))
}

func ConvertContainerPortsToNetworkPolicyPort(containerPorts []v1.ContainerPort) []netv1.NetworkPolicyPort {
	ports := lo.Map(containerPorts, func(containerPort v1.ContainerPort, idx int) netv1.NetworkPolicyPort {
		protocol := containerPort.Protocol
		port := intstr.FromInt(int(containerPort.ContainerPort))
		policyPort := netv1.NetworkPolicyPort{
			Port:     &port,
			Protocol: &protocol,
		}

		return policyPort
	})
	return lo.Uniq(ports)
}

func ConvertServicePortsToIngressNetworkPolicyPortForDebug(servicePorts []v1.ServicePort) []netv1.NetworkPolicyPort {
	return lo.Uniq(lo.FlatMap(servicePorts, func(item v1.ServicePort, index int) []netv1.NetworkPolicyPort {
		var ports []intstr.IntOrString

		if item.TargetPort.Type == 0 {
			if item.TargetPort.IntVal == 0 {
				ports = []intstr.IntOrString{intstr.FromInt(int(item.Port))}
			} else {
				ports = []intstr.IntOrString{intstr.FromInt(int(item.TargetPort.IntVal)), intstr.FromInt(int(item.Port))}
			}
		} else {
			ports = []intstr.IntOrString{intstr.FromString(item.TargetPort.StrVal), intstr.FromInt(int(item.Port))}
		}

		var protocols []v1.Protocol

		if item.Protocol == "" {
			protocols = append(protocols, v1.ProtocolTCP)
		} else {
			protocols = append(protocols, item.Protocol)
		}
		endpoints := []netv1.NetworkPolicyPort{}

		for _, port := range ports {
			for _, protocol := range protocols {
				x := port
				endpoints = append(endpoints, netv1.NetworkPolicyPort{
					Port:     &x,
					Protocol: &protocol,
				})
			}
		}
		return endpoints
	}))
}

func ConvertServicePortsToIngressNetworkPolicyPort(servicePorts []v1.ServicePort) []netv1.NetworkPolicyPort {
	return lo.Uniq(lo.FlatMap(servicePorts, func(item v1.ServicePort, index int) []netv1.NetworkPolicyPort {
		var port intstr.IntOrString
		if item.TargetPort.IntVal == 0 {
			if item.Name != "" {
				port = intstr.FromString(item.Name)
			} else {
				port = intstr.FromInt(int(item.Port))
			}
		} else {
			port = item.TargetPort
		}
		var protocols []v1.Protocol

		if item.Protocol == "" {
			protocols = append(protocols, v1.ProtocolTCP)
		} else {
			protocols = append(protocols, item.Protocol)
		}

		ports := lo.Map(protocols, func(item v1.Protocol, index int) netv1.NetworkPolicyPort {
			return netv1.NetworkPolicyPort{
				Port:     &port,
				Protocol: &item,
			}
		})
		targetPortName := item.TargetPort
		if item.TargetPort.StrVal != "" && item.TargetPort.StrVal != ports[0].Port.StrVal {
			ports_with_name := lo.Map(protocols, func(item v1.Protocol, index int) netv1.NetworkPolicyPort {
				return netv1.NetworkPolicyPort{
					Port:     &targetPortName,
					Protocol: &item,
				}
			})
			ports = append(ports, ports_with_name...)
		}
		return ports
	}))
}

func ConvertServicePortsToNetworkPolicyPort(servicePorts []v1.ServicePort) []netv1.NetworkPolicyPort {
	return lo.Uniq(lo.FlatMap(servicePorts, func(item v1.ServicePort, index int) []netv1.NetworkPolicyPort {
		port := intstr.FromInt(int(item.Port))
		var protocols []v1.Protocol

		if item.Protocol == "" {
			protocols = append(protocols, v1.ProtocolTCP)
		} else {
			protocols = append(protocols, item.Protocol)
		}

		var portName intstr.IntOrString
		if item.Name == "" {
			portName = port
		} else {
			portName = intstr.FromString(item.Name)
		}
		ports := lo.Uniq(lo.Map(protocols, func(item v1.Protocol, index int) netv1.NetworkPolicyPort {
			return netv1.NetworkPolicyPort{
				Port:     &portName,
				Protocol: &item,
			}
		}))
		targetPortName := item.TargetPort
		if item.TargetPort.StrVal != "" && item.TargetPort.StrVal != ports[0].Port.StrVal {
			ports_with_name := lo.Map(protocols, func(item v1.Protocol, index int) netv1.NetworkPolicyPort {
				return netv1.NetworkPolicyPort{
					Port:     &targetPortName,
					Protocol: &item,
				}
			})
			ports = append(ports, ports_with_name...)
		}
		return ports
	}))
}
