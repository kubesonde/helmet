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
package types

import (
	"fmt"
	"reflect"

	"helmet.io/pkg/helm"
	v1 "k8s.io/api/core/v1"
)

type Helmet struct {
	Manifests      helm.HelmManifestList
	HelmetLabel    string
	ManifestString string
}

type HelmET_ComputeUnit struct {
	Name           string
	Labels         map[string]string
	Namespace      string
	ContainerPorts []v1.ContainerPort
	EnvVars        []v1.EnvVar
	ConfigMaps     []string
	Arguments      []string
	Commands       []string
}
type HelmET_Service struct {
	Name         string
	Selector     map[string]string
	Labels       map[string]string
	ServicePorts []v1.ServicePort
	Headless     bool
}

type HelmET_Node struct {
	Name           string
	Namespace      string
	ComputeUnit    HelmET_ComputeUnit
	Services       []HelmET_Service
	DependencyName string
}

type NodesByName []HelmET_Node

func (node NodesByName) Len() int {
	return len(node)
}

func (node NodesByName) Less(i, j int) bool {
	return node[i].Name < node[j].Name
}

func (node NodesByName) Swap(i, j int) {
	node[i], node[j] = node[j], node[i]
}

type HelmET_Edge struct {
	Source             HelmET_Node
	Destination        HelmET_Node
	DestinationService HelmET_Service
	Port               int32
}

type EdgesByName []HelmET_Edge

func (edge EdgesByName) Len() int {
	return len(edge)
}

func (edge EdgesByName) Less(i, j int) bool {
	if edge[i].Source.Name == edge[j].Source.Name {
		return edge[i].Destination.Name < edge[j].Destination.Name
	}
	return edge[i].Source.Name < edge[j].Source.Name
}

func (edge EdgesByName) Swap(i, j int) {
	edge[i], edge[j] = edge[j], edge[i]
}

func (edge HelmET_Edge) toString() string {
	return fmt.Sprintf("%s_%s_%d", edge.Source.ComputeUnit.Name, edge.DestinationService.Name, edge.Port)
}

func (edge HelmET_Edge) EqualsNoPort(other_edge HelmET_Edge) bool {
	return reflect.DeepEqual(edge.Source, other_edge.Source) && reflect.DeepEqual(edge.Destination, other_edge.Destination)
}

func (edge HelmET_Edge) Equals(other_edge HelmET_Edge) bool {
	return edge.toString() == other_edge.toString()
}
