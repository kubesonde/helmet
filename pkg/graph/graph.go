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
package graph

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"helmet.io/pkg/core"
	"helmet.io/pkg/errors"
	"helmet.io/pkg/helm"
	"helmet.io/pkg/logging"
	"helmet.io/pkg/outbound"
	"helmet.io/pkg/types"
	"helmet.io/pkg/utils"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var log = logging.LOGGER.WithFields(logrus.Fields{
	"package": "graph",
})

func Type_of_edge(edge types.HelmET_Edge, ancestors map[string][]string) string {
	if edge.Source.DependencyName == edge.Destination.DependencyName {
		return "ITSELF"
	}

	for _, v := range ancestors[edge.Source.DependencyName] {
		if v == edge.Destination.DependencyName {
			return "CALLBACK"
		}
	}
	for _, v := range ancestors[edge.Destination.DependencyName] {
		if v == edge.Source.DependencyName {
			return "DESCENDANT"
		}
	}
	return "SIBLING"
}

func serviceInConfigMap(config_map string, serviceName string) bool {
	if strings.Contains(config_map, fmt.Sprintf("://%s:", serviceName)) {
		return true
	}
	if strings.Contains(config_map, fmt.Sprintf("%s\n", serviceName)) {
		return true
	}
	return false
}

func isServiceName(env_var string, serviceName string) bool {
	if env_var == serviceName {
		return true
	} else {
		if strings.Contains(env_var, serviceName) && strings.Contains(env_var, "cluster.local") {
			return true
		}

		if strings.Contains(env_var, fmt.Sprintf("://%s:", serviceName)) {
			return true
		}

		for _, field := range strings.Split(env_var, "=") {
			if field == serviceName {
				return true
			}
		}

		return strings.Contains(env_var, fmt.Sprintf("\"%s\"", serviceName))
	}
}

func ComputeEdgesWithEnvironmentVariables(manifestList helm.HelmManifestList, nodes []types.HelmET_Node) []types.HelmET_Edge {
	edges := []types.HelmET_Edge{}

	for _, src_node := range nodes {
		envVars := lo.FilterMap(src_node.ComputeUnit.EnvVars, func(variable v1.EnvVar, _ int) (string, bool) {
			if strings.Contains(strings.ToLower(variable.Name), "_user") || strings.Contains(strings.ToLower(variable.Name), "_database") ||
				strings.Contains(strings.ToLower(variable.Name), "_db") ||
				strings.Contains(variable.Name, "ELASTICSEARCH_CLUSTER_NAME") {
				return "", false
			}
			return variable.Value, true
		})

		env_and_args := append(append(envVars, src_node.ComputeUnit.Arguments...), src_node.ComputeUnit.Commands...)
		for _, value := range env_and_args {
			if value != "" {
				for _, dst_node := range nodes {
					if src_node.Name != dst_node.Name {
						for _, svc := range dst_node.Services {
							if isServiceName(value, svc.Name) {
								cleanedEnvVar := strings.ReplaceAll(value, svc.Name, "")

								re := regexp.MustCompile(`[:\[]\d{2,5}`)

								match := re.FindString(cleanedEnvVar)
								portMissing := true
								if match != "" {
									port, err := strconv.Atoi(match)
									if err == nil {
										portMissing = false
										edges = append(edges, types.HelmET_Edge{
											Source:      src_node,
											Destination: dst_node,
											Port:        lo.Must1(utils.IntToInt32(port)),
										})
									}
								}
								if portMissing {
									for _, svc_port := range svc.ServicePorts {
										edges = append(edges, types.HelmET_Edge{
											Source:      src_node,
											Destination: dst_node,
											Port:        svc_port.Port,
										})
									}
								}
							}
						}
					}
				}
			}
		}

		for _, configMap := range src_node.ComputeUnit.ConfigMaps {
			for _, dst_node := range nodes {
				if src_node.Name != dst_node.Name {
					for _, svc := range dst_node.Services {
						if serviceInConfigMap(configMap, svc.Name) {
							portMissing := true
							if portMissing {
								for _, svc_port := range svc.ServicePorts {
									edges = append(edges, types.HelmET_Edge{
										Source:             src_node,
										Destination:        dst_node,
										Port:               svc_port.Port,
										DestinationService: svc,
									})
								}
							}
						}
					}
				}
			}
		}
	}
	return lo.UniqBy(edges, func(edge types.HelmET_Edge) string {
		return fmt.Sprintf("%s-%s-%d", edge.DestinationService.Name, edge.Source.Name, edge.Port)
	})
}

func GetAcenstorsDescendants(manifestList helm.HelmManifestList) (map[string][]string, map[string][]string) {
	groupedManifests := helm.GroupManifestsByDependency(manifestList)

	descendants := map[string][]string{}
	ancestors := map[string][]string{}
	for _, dep := range lo.Keys(groupedManifests) {
		descendants[dep] = lo.Filter(lo.Keys(core.DependencyDescendantList(groupedManifests, dep)), func(val string, _ int) bool { return val != dep })
		ancestors[dep] = lo.Keys(core.DependencyAncestorList(groupedManifests, dep))
	}

	for dep, depManifestList := range groupedManifests {
		if !helm.ValidateMisconfigurationsInChart(depManifestList, false) {
			logging.LOGGER.WithFields(logrus.Fields{"Misconfig": "HostNetwork", "dependency": dep}).Info("STATS")
		}
	}

	return ancestors, descendants
}

func ComputeNodesFromDependency(dependencyName string, nodes []types.HelmET_Node) []types.HelmET_Node {
	return lo.Filter(nodes, func(node types.HelmET_Node, idx int) bool {
		return node.DependencyName == dependencyName
	})
}

func ComputeNodesPerDependency(dependencyNames []string, nodes []types.HelmET_Node) map[string][]types.HelmET_Node {
	nodesPerDependency := make(map[string][]types.HelmET_Node)
	for _, dependencyName := range dependencyNames {
		nodesPerDependency[dependencyName] = ComputeNodesFromDependency(dependencyName, nodes)
	}
	return nodesPerDependency
}

func ComputeEdges(sourceNodes []types.HelmET_Node, destNodes []types.HelmET_Node, edges []types.HelmET_Edge) []types.HelmET_Edge {
	for _, dest := range destNodes {
		for _, service := range dest.Services {
			for _, servicePort := range service.ServicePorts {
				for _, source := range sourceNodes {
					edges = append(edges, types.HelmET_Edge{
						Source:             source,
						Destination:        dest,
						Port:               servicePort.Port,
						DestinationService: service,
					})
				}
			}
		}
	}
	return edges
}

func ComputeEdgesToItself(manifestList helm.HelmManifestList, nodes []types.HelmET_Node) []types.HelmET_Edge {
	_, descendants := GetAcenstorsDescendants(manifestList)
	listOfDep := make([]string, 0, len(descendants))
	for key := range descendants {
		listOfDep = append(listOfDep, key)
	}
	nodesPerDependency := ComputeNodesPerDependency(listOfDep, nodes)
	return ComputeEdgesToItselfCompact(descendants, nodesPerDependency)
}

func ComputeEdgesToItselfCompact(descendants map[string][]string, nodesPerDependency map[string][]types.HelmET_Node) []types.HelmET_Edge {
	edges := []types.HelmET_Edge{}
	for item := range descendants {
		sourceNodes := nodesPerDependency[item]
		edges = ComputeEdges(sourceNodes, sourceNodes, edges)
	}
	return edges
}

func ComputeEdgesWithDependencyInformation(manifestList helm.HelmManifestList, nodes []types.HelmET_Node) []types.HelmET_Edge {
	_, descendants := GetAcenstorsDescendants(manifestList)
	listOfDep := make([]string, 0, len(descendants))
	for key := range descendants {
		listOfDep = append(listOfDep, key)
	}
	nodesPerDependency := ComputeNodesPerDependency(listOfDep, nodes)
	return ComputeEdgesWithDependencyInformationCompact(descendants, nodesPerDependency)
}

func ComputeEdgesWithDependencyInformationCompact(descendants map[string][]string, nodesPerDependency map[string][]types.HelmET_Node) []types.HelmET_Edge {
	edges := []types.HelmET_Edge{}
	for item, children := range descendants {
		sourceNodes := nodesPerDependency[item]
		for _, descendantDep := range children {
			destNodes := nodesPerDependency[descendantDep]
			edges = ComputeEdges(sourceNodes, destNodes, edges)
		}
	}
	return lo.UniqBy(edges, func(edge types.HelmET_Edge) string {
		return fmt.Sprintf("%s-%s-%d", edge.Destination.Name, edge.Source.Name, edge.Port)
	})
}

func GetHelmetNodesWithDependencies(manifestList helm.HelmManifestList) []types.HelmET_Node {
	nodes := []types.HelmET_Node{}
	groupedManifests := helm.GroupManifestsByDependency(manifestList)

	for dependency, manifests := range groupedManifests {
		helmetServices := outbound.GetHelmetServices(manifests)
		computeUnits := outbound.GetComputeUnitsDetails(manifests)
		for _, computeUnit := range computeUnits {
			var nodename string
			if len(computeUnit.Name) > 0 {
				nodename = computeUnit.Name
			} else {
				nodename = computeUnit.Labels["app.kubernetes.io/instance"]
			}
			node := types.HelmET_Node{
				Name:           nodename,
				ComputeUnit:    computeUnit,
				Services:       []types.HelmET_Service{},
				DependencyName: dependency,
				Namespace:      computeUnit.Namespace,
			}
			for _, service := range helmetServices {
				if lo.EveryBy(lo.Entries(service.Selector), func(entry lo.Entry[string, string]) bool {
					return computeUnit.Labels[entry.Key] == entry.Value
				}) {
					node.Services = append(node.Services, service)
					logging.LOGGER.WithFields(logrus.Fields{
						"dependency":       node.DependencyName,
						"cu_labels":        computeUnit.Labels,
						"cu_name":          computeUnit.Name,
						"cu_ports":         computeUnit.ContainerPorts,
						"service_selector": service.Selector,
						"service_name":     service.Name,
						"service_ports":    service.ServicePorts,
					}).Infof("NodeInformation")
				}
			}
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func CommonAndDisjoint(list1, list2 []types.HelmET_Edge) (common, disjointFromFirst, disjointFromSecond []types.HelmET_Edge) {
	matched := make(map[int]bool)

	for _, p1 := range list1 {
		found := false
		for j, p2 := range list2 {
			if p1.EqualsNoPort(p2) && !matched[j] {
				common = append(common, p1)
				matched[j] = true
				found = true
				break
			}
		}
		if !found {
			disjointFromFirst = append(disjointFromFirst, p1)
		}
	}

	for j, p2 := range list2 {
		if !matched[j] {
			disjointFromSecond = append(disjointFromSecond, p2)
		}
	}

	return common, disjointFromFirst, disjointFromSecond
}

func MergeGraphs(list1, list2 []types.HelmET_Edge) []types.HelmET_Edge {
	list_sum := append(list1, list2...)
	unique_edges := lo.UniqBy(list_sum, func(edge types.HelmET_Edge) string {
		return fmt.Sprintf("%s_%s_%d", edge.Source.Name, edge.Destination.Name, edge.Port)
	})
	return unique_edges
}

func edgeToNetworkPolicyEgress(edge types.HelmET_Edge) netv1.NetworkPolicy {
	toKubeSystemNS := netv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
		},
	}
	toAllNonPrivateAddresses := netv1.NetworkPolicyPeer{
		IPBlock: &netv1.IPBlock{
			CIDR:   "0.0.0.0/0",
			Except: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
	}
	port := intstr.FromInt(53)
	protoUDP := v1.ProtocolUDP
	protoTCP := v1.ProtocolTCP
	DNSuDPpOrt := netv1.NetworkPolicyPort{
		Port:     &port,
		Protocol: &protoUDP,
	}
	DNStCPpOrt := netv1.NetworkPolicyPort{
		Port:     &port,
		Protocol: &protoTCP,
	}
	policy := netv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.to.%s.%d", edge.Source.Name, edge.Destination.Name, edge.Port),
			Namespace: edge.Source.Namespace,
		},
	}
	policy.Spec = netv1.NetworkPolicySpec{}
	policy.Spec.PodSelector = metav1.LabelSelector{
		MatchLabels: edge.Source.ComputeUnit.Labels,
	}
	labelSelector := metav1.LabelSelector{
		MatchLabels: edge.Destination.ComputeUnit.Labels,
	}
	policy.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeEgress}
	netpolPort := getContainerPortMappingServicePort(edge.Destination, edge.DestinationService, int(edge.Port))
	edgeport := intstr.FromInt(int(edge.Port))
	proto := fixProto(*netpolPort.Protocol)
	policy.Spec.Egress = []netv1.NetworkPolicyEgressRule{
		{
			To: []netv1.NetworkPolicyPeer{toAllNonPrivateAddresses},
		},
		{
			To: []netv1.NetworkPolicyPeer{{
				PodSelector: &labelSelector,
			}},

			Ports: []netv1.NetworkPolicyPort{{
				Port:     netpolPort.Port,
				Protocol: &proto,
			}, {
				Port:     &edgeport,
				Protocol: &proto,
			}},
		},
		{
			To:    []netv1.NetworkPolicyPeer{toKubeSystemNS},
			Ports: []netv1.NetworkPolicyPort{DNSuDPpOrt, DNStCPpOrt},
		},
	}
	return policy
}

func fixProto(protocol v1.Protocol) v1.Protocol {
	if protocol == "" {
		return v1.ProtocolTCP
	}
	return protocol
}

func getContainerPortMappingServicePort(destnode types.HelmET_Node, destservice types.HelmET_Service, port int) netv1.NetworkPolicyPort {
	if destservice.Headless {
		targetContainerPort, _ := lo.Find(destnode.ComputeUnit.ContainerPorts, func(cport v1.ContainerPort) bool {
			return cport.ContainerPort == lo.Must1(utils.IntToInt32(port))
		})
		theport := intstr.FromInt(port)
		return netv1.NetworkPolicyPort{
			Port:     &theport,
			Protocol: &targetContainerPort.Protocol,
		}
	} else if len(destservice.ServicePorts) == 0 {
		log.Warnf("No service detected in compute unit %s - port %d", destnode.ComputeUnit.Name, port)
		targetContainerPort, found := lo.Find(destnode.ComputeUnit.ContainerPorts, func(cport v1.ContainerPort) bool {
			return cport.ContainerPort == lo.Must1(utils.IntToInt32(port))
		})
		if !found {
			log.WithField("error", errors.ServiceIssue).Errorf("There are no services and the container do not expose the port %d", port)
			theport := intstr.FromInt(port)
			theproto := v1.ProtocolTCP
			return netv1.NetworkPolicyPort{
				Port:     &theport,
				Protocol: &theproto,
			}
		}
		var proto v1.Protocol
		if len(targetContainerPort.Protocol) < 2 {
			proto = v1.ProtocolTCP
		} else {
			proto = targetContainerPort.Protocol
		}
		theport := intstr.FromInt(int(targetContainerPort.ContainerPort))
		netpolPort := netv1.NetworkPolicyPort{
			Port:     &theport,
			Protocol: &proto,
		}

		return netpolPort
	}
	targetServicePort, found := lo.Find(destservice.ServicePorts, func(svcport v1.ServicePort) bool {
		return svcport.Port == lo.Must1(utils.IntToInt32(port))
	})
	if !found {
		fmt.Println("ERRORRRR", port, destservice)
		os.Exit(1)
	}
	var proto v1.Protocol
	if len(targetServicePort.Protocol) < 2 {
		proto = v1.ProtocolTCP
	} else {
		proto = targetServicePort.Protocol
	}
	pport := targetServicePort.TargetPort
	if pport.IntVal == 0 {
		portName := pport.StrVal
		containerPort, found := lo.Find(destnode.ComputeUnit.ContainerPorts, func(cport v1.ContainerPort) bool {
			return cport.Name == portName
		})
		if found {
			theport := intstr.FromInt(int(containerPort.ContainerPort))
			return netv1.NetworkPolicyPort{
				Port:     &theport,
				Protocol: &containerPort.Protocol,
			}
		}
		logging.LOGGER.WithFields(logrus.Fields{"error": errors.MissingTargetPort, "service": destservice.Name, "port": targetServicePort.Port}).Errorf("Service %s has no target port %d", destservice.Name, targetServicePort.Port)
		pport = intstr.FromInt(int(targetServicePort.Port))
	}

	netpolPort := netv1.NetworkPolicyPort{
		Port:     &pport,
		Protocol: &proto,
	}

	return netpolPort
}

func edgeToNetworkPolicyIngress(edge types.HelmET_Edge) netv1.NetworkPolicy {
	policy := netv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.from.%s.%d", edge.Destination.Name, edge.Source.Name, edge.Port),
			Namespace: edge.Destination.Namespace,
		},
	}
	policy.Spec = netv1.NetworkPolicySpec{}
	policy.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeIngress}
	policy.Spec.PodSelector = metav1.LabelSelector{
		MatchLabels: edge.Destination.ComputeUnit.Labels,
	}
	labelSelector := metav1.LabelSelector{
		MatchLabels: edge.Source.ComputeUnit.Labels,
	}

	netpolPort := getContainerPortMappingServicePort(edge.Destination, edge.DestinationService, int(edge.Port))
	edgeport := intstr.FromInt(int(edge.Port))
	proto := fixProto(*netpolPort.Protocol)
	policy.Spec.Ingress = []netv1.NetworkPolicyIngressRule{{
		From: []netv1.NetworkPolicyPeer{{
			PodSelector: &labelSelector,
		}},

		Ports: []netv1.NetworkPolicyPort{
			{
				Port:     netpolPort.Port,
				Protocol: &proto,
			},
			{
				Port:     &edgeport,
				Protocol: &proto,
			},
		},
	}}
	return policy
}

func EdgeToNetworkPolicy(edge types.HelmET_Edge) []netv1.NetworkPolicy {
	egress := edgeToNetworkPolicyEgress(edge)
	ingress := edgeToNetworkPolicyIngress(edge)

	return []netv1.NetworkPolicy{egress, ingress}
}

func EdgesToNetworkPolicy(edges []types.HelmET_Edge) []netv1.NetworkPolicy {
	mappedEdges := lo.Map(edges, func(edge types.HelmET_Edge, index int) []netv1.NetworkPolicy {
		return EdgeToNetworkPolicy(edge)
	})
	return lo.Flatten(mappedEdges)
}

func ProcessChart(manifestList helm.HelmManifestList) []netv1.NetworkPolicy {
	ancestors, descendants := GetAcenstorsDescendants(manifestList)
	log.
		WithFields(logrus.Fields{"dependencies": lo.Keys(ancestors), "descendants": descendants, "ancestors": ancestors}).
		Infof("Dependencies have been correctly computed")
	nodes := GetHelmetNodesWithDependencies(manifestList)

	nlen := len(outbound.GetNetworkPolicies(manifestList))
	if nlen > 0 {
		log.WithFields(logrus.Fields{"networkPolicy": nlen}).Infof("Chart has network policies")
	}

	listOfDep := make([]string, 0, len(descendants))
	for key := range descendants {
		listOfDep = append(listOfDep, key)
	}
	nodesPerDependency := ComputeNodesPerDependency(listOfDep, nodes)

	edgesItself := ComputeEdgesToItselfCompact(descendants, nodesPerDependency)

	edgesDep := ComputeEdgesWithDependencyInformationCompact(descendants, nodesPerDependency)

	edgesEnvVar := ComputeEdgesWithEnvironmentVariables(manifestList, nodes)

	final_graph := MergeGraphs(edgesDep, edgesItself)
	final_graph = MergeGraphs(final_graph, edgesEnvVar)

	commonEdges, onlyDep, onlyEnvVar := CommonAndDisjoint(edgesDep, edgesEnvVar)

	for _, edge := range commonEdges {
		log.
			WithFields(logrus.Fields{
				"source":      edge.Source.Name,
				"destination": edge.Destination.Name,
				"port":        edge.Port,
				"type":        Type_of_edge(edge, ancestors),
				"origin":      "common",
			},
			).
			Infof("(%s) %s -%d➡ %s", Type_of_edge(edge, ancestors), edge.Source.Name, edge.Port, edge.Destination.Name)
	}

	if len(onlyDep) > 0 {
		for _, edge := range onlyDep {
			log.
				WithFields(logrus.Fields{
					"source":      edge.Source.Name,
					"destination": edge.Destination.Name,
					"port":        edge.Port,
					"type":        Type_of_edge(edge, ancestors),
					"origin":      "dependency",
				},
				).
				Infof("(%s) %s -%d➡ %s", Type_of_edge(edge, ancestors), edge.Source.Name, edge.Port, edge.Destination.Name)
		}
	}
	if len(onlyEnvVar) > 0 {
		for _, edge := range onlyEnvVar {
			log.
				WithFields(logrus.Fields{
					"source":      edge.Source.Name,
					"destination": edge.Destination.Name,
					"port":        edge.Port,
					"type":        Type_of_edge(edge, ancestors),
					"origin":      "environment",
				},
				).
				Infof("(%s) %s -%d➡ %s", Type_of_edge(edge, ancestors), edge.Source.Name, edge.Port, edge.Destination.Name)
		}
	}

	policies := EdgesToNetworkPolicy(final_graph)

	if len(outbound.GetObjects(manifestList, "ClusterRole")) > 0 {
		kubeapi_policies := lo.Map(nodes, func(node types.HelmET_Node, _ int) netv1.NetworkPolicy {
			labelSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"component": "kube-apiserver"},
			}
			log.WithFields(logrus.Fields{
				"source":      node.Name,
				"destination": "kube-apiserver",
				"port":        "any",
				"type":        "EXTERNAL",
				"origin":      "custom",
			},
			).Infof("(CUSTOM) %s -any➡ kube-apiserver", node.Name)
			return netv1.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "networking.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s.to.apiserver", node.Name),
					Namespace: node.ComputeUnit.Namespace,
				},
				Spec: netv1.NetworkPolicySpec{
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					PodSelector: metav1.LabelSelector{
						MatchLabels: node.ComputeUnit.Labels,
					},
					Egress: []netv1.NetworkPolicyEgressRule{
						{
							To: []netv1.NetworkPolicyPeer{{
								PodSelector: &labelSelector,
							}},
						}, {
							To: []netv1.NetworkPolicyPeer{
								{
									IPBlock: &netv1.IPBlock{
										CIDR: "10.96.0.1/32",
									},
								},
								{
									IPBlock: &netv1.IPBlock{
										CIDR: "192.168.0.0/16",
									},
								},
							},
						},
					},
				},
			}
		})

		policies = append(policies, kubeapi_policies...)
	}

	return policies
}
