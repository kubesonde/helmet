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
	"sort"
	"testing"

	"gotest.tools/v3/assert"
	"helmet.io/pkg/helm"
	"helmet.io/pkg/testutils"
	"helmet.io/pkg/types"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func Test_serviceInConfigMap(t *testing.T) {
	assert.Equal(t, serviceInConfigMap("somestrings then http://myservice:80", "myservice"), true)
	assert.Equal(t, serviceInConfigMap("somestrings then http://myservice1:80", "myservice"), false)
	assert.Equal(t, serviceInConfigMap("myservice then http://:80", "myservice"), false)
	assert.Equal(t, serviceInConfigMap("this is myservice", "myservice"), false)
	assert.Equal(t, serviceInConfigMap("this is myservice\n", "myservice"), true)
}

func Test_isServiceName(t *testing.T) {
	assert.Equal(t, isServiceName("myservice", "myservice"), true)
	assert.Equal(t, isServiceName("myservice.default.svc.cluster.local", "myservice"), true)
	assert.Equal(t, isServiceName("myservice.flyte.svc.cluster.local", "myservice"), true)
	assert.Equal(t, isServiceName("var=myservice", "myservice"), true)
	assert.Equal(t, isServiceName("var=\"myservice\"", "myservice"), true)
	assert.Equal(t, isServiceName("http://myservice:80", "myservice"), true)
	assert.Equal(t, isServiceName("myservice_db", "myservice"), false)
}

func TestGetAcenstorsDescendants(t *testing.T) {
	manifestList := helm.HelmManifestList{
		"chart1/charts/chart2/templates/app.yaml": {},
		"chart1/templates/app.yaml":               {},
	}
	asc, desc := GetAcenstorsDescendants(manifestList)
	assert.DeepEqual(t, asc, map[string][]string{"chart1": {}, "chart1_chart2": {"chart1"}})
	assert.DeepEqual(t, desc, map[string][]string{"chart1": {"chart1_chart2"}, "chart1_chart2": {}})
}

func TestGetHelmetNodesWithDependencies(t *testing.T) {
	manifestList := helm.GetManifestListFromString(testutils.WORDPRESS)
	nodes := GetHelmetNodesWithDependencies(manifestList)
	sort.Sort(types.NodesByName(nodes))
	assert.Equal(t, len(nodes), 2)
	assert.Equal(t, nodes[0].Name, "mychart-mariadb")
	assert.Equal(t, nodes[1].Name, "mychart-wordpress")
	assert.Equal(t, nodes[0].DependencyName, "wordpress_mariadb")
	assert.Equal(t, nodes[1].DependencyName, "wordpress")
}

func TestComputeEdgesToItself(t *testing.T) {
	manifestList := helm.GetManifestListFromString(testutils.WORDPRESS)
	nodes := GetHelmetNodesWithDependencies(manifestList)

	edges := ComputeEdgesToItself(manifestList, nodes)
	sort.Sort(types.EdgesByName(edges))
	assert.Equal(t, len(edges), 3)
	assert.Equal(t, edges[0].Port, int32(3306))
	assert.Equal(t, edges[0].Source.Name, "mychart-mariadb")
	assert.Equal(t, edges[0].Destination.Name, "mychart-mariadb")
	assert.Equal(t, edges[1].Port, int32(80))
	assert.Equal(t, edges[1].Source.Name, "mychart-wordpress")
	assert.Equal(t, edges[1].Destination.Name, "mychart-wordpress")
	assert.Equal(t, edges[2].Port, int32(443))
	assert.Equal(t, edges[2].Source.Name, "mychart-wordpress")
	assert.Equal(t, edges[2].Destination.Name, "mychart-wordpress")
}

func TestComputeEdgesWithDependencyInformation(t *testing.T) {
	manifestList := helm.GetManifestListFromString(testutils.WORDPRESS)
	nodes := GetHelmetNodesWithDependencies(manifestList)
	edges := ComputeEdgesWithDependencyInformation(manifestList, nodes)
	sort.Sort(types.EdgesByName(edges))
	assert.Equal(t, len(edges), 1)
	assert.Equal(t, edges[0].Port, int32(3306))
	assert.Equal(t, edges[0].Source.Name, "mychart-wordpress")
	assert.Equal(t, edges[0].Destination.Name, "mychart-mariadb")
}

func TestComputeEdgesWithEnvironmentVariables(t *testing.T) {
	manifestList := helm.GetManifestListFromString(testutils.WORDPRESS)
	nodes := GetHelmetNodesWithDependencies(manifestList)
	edges := ComputeEdgesWithEnvironmentVariables(manifestList, nodes)

	assert.Equal(t, len(edges), 1)
	assert.Equal(t, edges[0].Port, int32(3306))
	assert.Equal(t, edges[0].Source.Name, "mychart-wordpress")
	assert.Equal(t, edges[0].Destination.Name, "mychart-mariadb")
}

func TestCommonAndDisjoint(t *testing.T) {
	manifestList := helm.GetManifestListFromString(testutils.WORDPRESS)
	nodes := GetHelmetNodesWithDependencies(manifestList)
	edgesE := ComputeEdgesWithEnvironmentVariables(manifestList, nodes)

	edgesD := ComputeEdgesWithDependencyInformation(manifestList, nodes)

	c, de, dd := CommonAndDisjoint(edgesE, edgesD)
	assert.Equal(t, len(c), 1)
	assert.Equal(t, len(de), 0)
	assert.Equal(t, len(dd), 0)
}

func SkipTestEdgeToNetworkPolicyEgress(t *testing.T) {
	manifestList := helm.GetManifestListFromString(testutils.WORDPRESS)
	nodes := GetHelmetNodesWithDependencies(manifestList)
	edges := ComputeEdgesWithDependencyInformation(manifestList, nodes)
	sort.Sort(types.EdgesByName(edges))

	egress := edgeToNetworkPolicyEgress(edges[0])
	// Name is correct
	assert.Equal(t, egress.Name, "mychart-wordpress.to.mychart-mariadb.3306")
	// There is no ingress
	assert.Equal(t, len(egress.Spec.Ingress), 0)
	// There are two egress. One for the pod and one for the DNS
	assert.Equal(t, len(egress.Spec.Egress), 2)
	// We are selecting the right pods
	assert.DeepEqual(t, egress.Spec.PodSelector.MatchLabels, edges[0].Source.ComputeUnit.Labels)
	eg := egress.Spec.Egress[0]
	assert.Equal(t, len(eg.To), 1)
	assert.DeepEqual(t, eg.To[0].PodSelector.MatchLabels, edges[0].Destination.ComputeUnit.Labels)
}

func TestEdgeToNetworkPolicyIngress(t *testing.T) {
	manifestList := helm.GetManifestListFromString(testutils.WORDPRESS)
	nodes := GetHelmetNodesWithDependencies(manifestList)
	edges := ComputeEdgesWithDependencyInformation(manifestList, nodes)

	sort.Sort(types.EdgesByName(edges))

	ingress := edgeToNetworkPolicyIngress(edges[0])
	// Name is correct
	assert.Equal(t, ingress.Name, "mychart-mariadb.from.mychart-wordpress.3306")
	// There is no ingress
	assert.Equal(t, len(ingress.Spec.Ingress), 1)
	// There is only one egress
	assert.Equal(t, len(ingress.Spec.Egress), 0)
	// We are selecting the right pods
	assert.DeepEqual(t, ingress.Spec.PodSelector.MatchLabels, edges[0].Destination.ComputeUnit.Labels)
	ig := ingress.Spec.Ingress[0]
	assert.Equal(t, len(ig.From), 1)
	assert.DeepEqual(t, ig.From[0].PodSelector.MatchLabels, edges[0].Source.ComputeUnit.Labels)
}

func TestEdgesToNetworkPolicy(t *testing.T) {
	manifestList := helm.GetManifestListFromString(testutils.WORDPRESS)
	nodes := GetHelmetNodesWithDependencies(manifestList)
	edgesA := ComputeEdgesWithDependencyInformation(manifestList, nodes)

	_, descendants := GetAcenstorsDescendants(manifestList)
	listOfDep := make([]string, 0, len(descendants))
	for key := range descendants {
		listOfDep = append(listOfDep, key)
	}
	nodesPerDependency := ComputeNodesPerDependency(listOfDep, nodes)
	edgesItself := ComputeEdgesToItselfCompact(descendants, nodesPerDependency)
	edges := MergeGraphs(edgesA, edgesItself)
	assert.Equal(t, len(edges), 4)
	sort.Sort(types.EdgesByName(edges))

	edge1 := edges[0]
	assert.Equal(t, edge1.Source.Name, "mychart-mariadb")
	assert.Equal(t, edge1.Destination.Name, "mychart-mariadb")

	policies := EdgesToNetworkPolicy(edges)
	assert.Equal(t, len(policies), 8)
}

func TestGetContainerPortMappingServicePort(t *testing.T) {
	node := types.HelmET_Node{
		ComputeUnit: types.HelmET_ComputeUnit{
			ContainerPorts: []v1.ContainerPort{{
				ContainerPort: 8080,
			}},
		},
	}

	service := types.HelmET_Service{
		ServicePorts: []v1.ServicePort{{
			Port:       80,
			TargetPort: intstr.FromInt(8080),
			Protocol:   v1.ProtocolTCP,
		}},
	}

	port := 80

	netpolPort := getContainerPortMappingServicePort(node, service, port)

	assert.Equal(t, netpolPort.Port.IntVal, intstr.FromInt(8080).IntVal)
}
