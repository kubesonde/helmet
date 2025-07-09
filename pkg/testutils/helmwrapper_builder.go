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
package testutils

import (
	"fmt"

	"github.com/samber/lo"
	"helmet.io/pkg/helm"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

type Chart struct {
	manifests helm.HelmManifestList
	Name      string
	deps      []Chart
}

func NewChart(name string) *Chart {
	c := new(Chart)
	c.init()
	c.Name = name
	return c
}

func (c *Chart) AddService(service v1.Service, name string) {
	svc_bytes := lo.Must1(yaml.Marshal(service))
	var manifest helm.HelmManifest
	lo.Must0(yaml.Unmarshal(svc_bytes, &manifest))
	c.manifests[name] = manifest
}

func (c *Chart) AddPod(pod v1.Pod, name string) {
	pod_bytes := lo.Must1(yaml.Marshal(pod))
	var manifest helm.HelmManifest
	lo.Must0(yaml.Unmarshal(pod_bytes, &manifest))
	c.manifests[name] = manifest
}

func (c *Chart) Build() helm.HelmManifestList {
	updated_manifests := helm.HelmManifestList{}
	for k, v := range c.manifests {
		updated_manifests[fmt.Sprintf("%s/templates/%s", c.Name, k)] = v
	}
	for _, dependency := range c.deps {
		for k, v := range dependency.manifests {
			updated_manifests[fmt.Sprintf("%s/charts/%s/templates/%s", c.Name, dependency.Name, k)] = v
		}
	}
	return updated_manifests
}

func (c *Chart) init() {
	c.manifests = make(helm.HelmManifestList)
	c.deps = []Chart{}
}

func (c *Chart) AddDependency(dep Chart) {
	c.deps = append(c.deps, dep)
}

func (c *Chart) IsEmpty() bool {
	return len(lo.Keys(c.manifests)) == 0
}

func ToNetworkPolicy(policy string) netv1.NetworkPolicy {
	var netpol netv1.NetworkPolicy
	err := yaml.Unmarshal([]byte(policy), &netpol)
	if err != nil {
		fmt.Println(err.Error())
		return netv1.NetworkPolicy{}
	}
	return netpol
}

func ToPod(pod string) v1.Pod {
	var thePod v1.Pod
	err := yaml.Unmarshal([]byte(pod), &thePod)
	if err != nil {
		fmt.Println(err.Error())
		return thePod
	}
	return thePod
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

func GetKubeSystemRule() netv1.NetworkPolicyEgressRule {
	pudp := v1.ProtocolUDP
	ptcp := v1.ProtocolTCP
	port := intstr.FromInt(53)

	return netv1.NetworkPolicyEgressRule{
		To: []netv1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
			},
		},
		Ports: []netv1.NetworkPolicyPort{
			{
				Port:     &port,
				Protocol: &pudp,
			},
			{
				Port:     &port,
				Protocol: &ptcp,
			},
		},
	}
}

func GetInternetRule() netv1.NetworkPolicyEgressRule {
	return netv1.NetworkPolicyEgressRule{
		To: []netv1.NetworkPolicyPeer{
			{
				IPBlock: &netv1.IPBlock{
					CIDR:   "0.0.0.0/0",
					Except: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				},
			},
		},
	}
}
