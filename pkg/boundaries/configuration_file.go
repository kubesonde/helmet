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
package boundaries

import (
	"fmt"
	"os"
	"reflect"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"helmet.io/pkg/core"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

var dependencyLabelKey = "helmet.io/chart"

type HelmETConfig struct {
	Name              string            `yaml:"Name"`
	ComponentSelector map[string]string `yaml:"ComponentSelector"`
	Interactions      []Interaction     `yaml:"Interactions,omitempty"`
	Ingress           NetworkInterface  `yaml:"Ingress,omitempty"`
	Egress            NetworkInterface  `yaml:"Egress,omitempty"`
}

type Interaction struct {
	From map[string]string `yaml:"From,omitempty"`
	To   map[string]string `yaml:"To,omitempty"`
}
type Resource struct {
	Selector map[string]string         `yaml:"selector,omitempty"`
	Ports    []netv1.NetworkPolicyPort `yaml:"ports,omitempty"`
}
type Deny struct {
	Components []string   `yaml:"component,omitempty"`
	Resources  []Resource `yaml:"resource,omitempty"`
}
type Allow struct {
	Components []string   `yaml:"component,omitempty"`
	Resources  []Resource `yaml:"resource,omitempty"`
}
type NetworkInterface struct {
	Deny  Deny  `yaml:"deny,omitempty"`
	Allow Allow `yaml:"allow,omitempty"`
}

func is_dependendency(rule netv1.NetworkPolicyEgressRule) bool {
	return len(rule.To) == 1 && rule.To[0].IPBlock == nil
}

func is_dependant(rule netv1.NetworkPolicyIngressRule) bool {
	return len(rule.From) == 1 && rule.From[0].IPBlock == nil
}

func MapNetpolToCustomFormat(netpol netv1.NetworkPolicy, log *logrus.Entry) *HelmETConfig {
	config := HelmETConfig{}
	config.Name = netpol.Name
	config.ComponentSelector = netpol.Spec.PodSelector.MatchLabels

	for _, ingressRule := range netpol.Spec.Ingress {
		if len(ingressRule.From) > 0 && is_dependant(ingressRule) {
			if config.Ingress.Allow.Resources == nil {
				config.Ingress.Allow.Resources = []Resource{}
			}
			if len(ingressRule.Ports) == 0 {
				continue
			}
			selector := map[string]string{}
			if ingressRule.From[0].PodSelector != nil {
				selector = ingressRule.From[0].PodSelector.MatchLabels
			}
			config.Ingress.Allow.Resources = append(config.Ingress.Allow.Resources, Resource{Selector: selector, Ports: ingressRule.Ports})
		} else {
			for _, source := range ingressRule.From {
				if source.PodSelector != nil {
					if source.PodSelector.MatchLabels[dependencyLabelKey] == config.ComponentSelector[dependencyLabelKey] {
						config.Ingress.Allow.Components = append(config.Ingress.Allow.Components, "chart_pods")
					} else {
						config.Ingress.Allow.Resources = append(config.Ingress.Allow.Resources, Resource{Selector: source.PodSelector.MatchLabels, Ports: ingressRule.Ports})
					}
				} else {
					config.Ingress.Allow.Resources = append(config.Ingress.Allow.Resources, Resource{Ports: ingressRule.Ports, Selector: source.PodSelector.MatchLabels})
				}
			}
		}
	}

	for _, egressRule := range netpol.Spec.Egress {
		if len(egressRule.Ports) == 1 && egressRule.Ports[0].Port.IntVal == 8443 {
			config.Egress.Allow.Components = append(config.Egress.Allow.Components, "kube_api_server")
		} else if len(egressRule.Ports) == 2 && egressRule.Ports[0].Port.IntVal == 53 {
			config.Egress.Allow.Components = append(config.Egress.Allow.Components, "dns")
		} else if is_dependendency(egressRule) {
			if len(egressRule.Ports) == 0 {
				continue
			}
			selector := map[string]string{}
			if egressRule.To[0].PodSelector != nil {
				selector = egressRule.To[0].PodSelector.MatchLabels
			}
			config.Egress.Allow.Resources = append(config.Egress.Allow.Resources, Resource{Selector: selector, Ports: egressRule.Ports})
		} else {
			for _, source := range egressRule.To {
				if source.IPBlock != nil && source.IPBlock.CIDR == "0.0.0.0/0" && reflect.DeepEqual(source.IPBlock.Except, []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}) {
					config.Egress.Deny.Components = append(config.Egress.Deny.Components, "private_subnets")
				} else if source.PodSelector != nil {
					if source.PodSelector.MatchLabels[dependencyLabelKey] == config.ComponentSelector[dependencyLabelKey] {
						config.Egress.Allow.Components = append(config.Egress.Allow.Components, "chart_pods")
					}
				}
			}
		}
	}
	return &config
}

func CustomFormatToNetpol(config HelmETConfig, client kubernetes.Interface) netv1.NetworkPolicy {
	kubernetesIP, kubernetesPort := core.GetKubernetesIPAndPort(client)

	pudp := corev1.ProtocolUDP
	ptcp := corev1.ProtocolTCP
	port := intstr.FromInt(53)
	kport := intstr.FromInt(int(kubernetesPort))

	policy := netv1.NetworkPolicy{
		TypeMeta: v1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: config.Name,
		},
		Spec: netv1.NetworkPolicySpec{
			Ingress: []netv1.NetworkPolicyIngressRule{},
			Egress:  []netv1.NetworkPolicyEgressRule{},
			PolicyTypes: []netv1.PolicyType{
				netv1.PolicyTypeEgress, netv1.PolicyTypeIngress,
			},
			PodSelector: v1.LabelSelector{MatchLabels: config.ComponentSelector},
		},
	}

	for _, inboundAllowcomponent := range config.Ingress.Allow.Components {
		if inboundAllowcomponent == "chart_pods" {
			policy.Spec.Ingress = append(policy.Spec.Ingress, netv1.NetworkPolicyIngressRule{
				From: []netv1.NetworkPolicyPeer{
					{
						PodSelector: &v1.LabelSelector{MatchLabels: config.ComponentSelector},
					},
				},
			})
		}
	}
	for _, inboundAllowResource := range config.Ingress.Allow.Resources {
		policy.Spec.Ingress = append(policy.Spec.Ingress, netv1.NetworkPolicyIngressRule{
			Ports: inboundAllowResource.Ports,
			From: []netv1.NetworkPolicyPeer{
				{PodSelector: &v1.LabelSelector{
					MatchLabels: inboundAllowResource.Selector,
				}},
			},
		})
	}

	for _, outboundAllowcomponent := range config.Egress.Allow.Components {
		if outboundAllowcomponent == "chart_pods" {
			policy.Spec.Egress = append(policy.Spec.Egress, netv1.NetworkPolicyEgressRule{
				To: []netv1.NetworkPolicyPeer{
					{
						PodSelector: &v1.LabelSelector{MatchLabels: config.ComponentSelector},
					},
				},
			})
		}
		if outboundAllowcomponent == "dns" {
			policy.Spec.Egress = append(policy.Spec.Egress, netv1.NetworkPolicyEgressRule{
				To: []netv1.NetworkPolicyPeer{
					{
						NamespaceSelector: &v1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
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
			})
		}
		if outboundAllowcomponent == "kube_api_server" {
			policy.Spec.Egress = append(policy.Spec.Egress, netv1.NetworkPolicyEgressRule{
				To: []netv1.NetworkPolicyPeer{{
					IPBlock: &netv1.IPBlock{
						CIDR: fmt.Sprintf("%s/32", kubernetesIP),
					},
				}},
				Ports: []netv1.NetworkPolicyPort{{Port: &kport}},
			})
		}
	}
	for _, outboundDenycomponent := range config.Egress.Deny.Components {
		if outboundDenycomponent == "private_subnets" {
			policy.Spec.Egress = append(policy.Spec.Egress, netv1.NetworkPolicyEgressRule{
				To: []netv1.NetworkPolicyPeer{
					{
						IPBlock: &netv1.IPBlock{
							CIDR:   "0.0.0.0/0",
							Except: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
						},
					},
				},
			})
		}
	}

	return policy
}

func NetworkPoliciesToTemplate(netpols []netv1.NetworkPolicy, depTree map[string][]string) []HelmETConfig {
	configs := []HelmETConfig{}
	for _, netpol := range netpols {
		config := HelmETConfig{}
		config.Name = netpol.Name
		config.ComponentSelector = netpol.Spec.PodSelector.MatchLabels
		config.Ingress.Allow = Allow{
			Resources: []Resource{},
		}
		for _, ingress := range netpol.Spec.Ingress {
			if len(ingress.Ports) > 0 {
				config.Ingress.Allow.Resources = append(config.Ingress.Allow.Resources, Resource{Ports: lo.UniqBy(ingress.Ports, func(port netv1.NetworkPolicyPort) string {
					return port.String() + string(*port.Protocol)
				})})
			}
		}
		for _, egressRule := range netpol.Spec.Egress {
			if len(egressRule.Ports) == 1 && egressRule.Ports[0].Port.IntVal == 8443 {
				config.Egress.Allow.Components = append(config.Egress.Allow.Components, "kube_api_server")
			} else if len(egressRule.Ports) == 2 && egressRule.Ports[0].Port.IntVal == 53 {
				config.Egress.Allow.Components = append(config.Egress.Allow.Components, "dns")
			} else {
				for _, source := range egressRule.To {
					if source.IPBlock != nil && source.IPBlock.CIDR == "0.0.0.0/0" && reflect.DeepEqual(source.IPBlock.Except, []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}) {
						config.Egress.Deny.Components = append(config.Egress.Deny.Components, "private_subnets")
					}
				}
			}
		}
		curr_dep := config.ComponentSelector["helmet.io/chart"]
		val, ok := depTree[curr_dep]
		if ok {
			config.Interactions = []Interaction{}
			for _, dep := range val {
				config.Interactions = append(config.Interactions, Interaction{
					From: map[string]string{"helmet.io/chart": curr_dep},
					To:   map[string]string{"helmet.io/chart": dep},
				})
			}
		}

		configs = append(configs, config)
	}
	return configs
}

func generatePolicySkeleton(policyName string, name string) netv1.NetworkPolicy {
	return netv1.NetworkPolicy{
		TypeMeta: v1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: policyName,
		},
		Spec: netv1.NetworkPolicySpec{
			Ingress: []netv1.NetworkPolicyIngressRule{},
			Egress:  []netv1.NetworkPolicyEgressRule{},
			PolicyTypes: []netv1.PolicyType{
				netv1.PolicyTypeEgress, netv1.PolicyTypeIngress,
			},
			PodSelector: v1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": name}},
		},
	}
}

func TemplatesToNetpol(configs []HelmETConfig, client kubernetes.Interface, ancestors map[string][]string) []netv1.NetworkPolicy {
	kubernetesIP, kubernetesPort := core.GetKubernetesIPAndPort(client)

	pudp := corev1.ProtocolUDP
	ptcp := corev1.ProtocolTCP
	port := intstr.FromInt(53)
	kport := intstr.FromInt(int(kubernetesPort))
	policies := map[string]netv1.NetworkPolicy{}
	ingresses := map[string][]netv1.NetworkPolicyPort{}

	for _, config := range configs {
		curr_dep := config.ComponentSelector["helmet.io/chart"]
		_, ok := ancestors[curr_dep]
		policy := generatePolicySkeleton(config.Name, curr_dep)
		if config.Ingress.Allow.Resources != nil {
			ingresses[curr_dep] = config.Ingress.Allow.Resources[0].Ports
		}
		for _, inboundAllowcomponent := range config.Ingress.Allow.Components {
			if inboundAllowcomponent == "chart_pods" {
				policy.Spec.Ingress = append(policy.Spec.Ingress, netv1.NetworkPolicyIngressRule{
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &v1.LabelSelector{MatchLabels: config.ComponentSelector},
						},
					},
				})
			}
		}

		policy.Spec.Ingress = append(policy.Spec.Ingress, netv1.NetworkPolicyIngressRule{
			From: []netv1.NetworkPolicyPeer{
				{PodSelector: &v1.LabelSelector{
					MatchLabels: config.ComponentSelector,
				}},
			},
		})

		for _, outboundDenycomponent := range config.Egress.Deny.Components {
			if outboundDenycomponent == "private_subnets" {
				policy.Spec.Egress = append(policy.Spec.Egress, netv1.NetworkPolicyEgressRule{
					To: []netv1.NetworkPolicyPeer{
						{
							IPBlock: &netv1.IPBlock{
								CIDR:   "0.0.0.0/0",
								Except: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
							},
						},
					},
				})
			}
		}

		if !ok {
			for _, inboundAllowResource := range config.Ingress.Allow.Resources {
				policy.Spec.Ingress = append(policy.Spec.Ingress, netv1.NetworkPolicyIngressRule{
					Ports: inboundAllowResource.Ports,
					From: []netv1.NetworkPolicyPeer{
						{PodSelector: &v1.LabelSelector{
							MatchLabels: inboundAllowResource.Selector,
						}},
					},
				})
			}
		}

		for _, outboundAllowcomponent := range config.Egress.Allow.Components {
			if outboundAllowcomponent == "dns" {
				policy.Spec.Egress = append(policy.Spec.Egress, netv1.NetworkPolicyEgressRule{
					To: []netv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &v1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
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
				})
			}
			if outboundAllowcomponent == "kube_api_server" {
				policy.Spec.Egress = append(policy.Spec.Egress, netv1.NetworkPolicyEgressRule{
					To: []netv1.NetworkPolicyPeer{{
						IPBlock: &netv1.IPBlock{
							CIDR: fmt.Sprintf("%s/32", kubernetesIP),
						},
					}},
					Ports: []netv1.NetworkPolicyPort{{Port: &kport}},
				})
			}
		}

		policy.Spec.Egress = append(policy.Spec.Egress, netv1.NetworkPolicyEgressRule{
			To: []netv1.NetworkPolicyPeer{
				{
					PodSelector: &v1.LabelSelector{MatchLabels: config.ComponentSelector},
				},
			},
		})

		policies[curr_dep] = policy
	}

	for _, config := range configs {
		if config.Interactions != nil {
			for _, interaction := range config.Interactions {
				from := interaction.From
				to := interaction.To
				from_chart := interaction.From["helmet.io/chart"]
				to_chart := interaction.To["helmet.io/chart"]

				destination := policies[to_chart]
				destination.Spec.Ingress = append(destination.Spec.Ingress, netv1.NetworkPolicyIngressRule{
					Ports: ingresses[to_chart],
					From:  []netv1.NetworkPolicyPeer{{PodSelector: &v1.LabelSelector{MatchLabels: from}}},
				})
				policies[to_chart] = destination

				source := policies[from_chart]
				source.Spec.Egress = append(source.Spec.Egress, netv1.NetworkPolicyEgressRule{
					Ports: ingresses[to_chart],
					To:    []netv1.NetworkPolicyPeer{{PodSelector: &v1.LabelSelector{MatchLabels: to}}},
				})
				policies[from_chart] = source
			}
		}
	}
	return lo.Values(policies)
}

func WriteHelmETConfigsToYAML(configs []HelmETConfig, filePath string) error {
	data, err := yaml.Marshal(configs)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0o600)
}

func ReadHelmETConfigsFromYAML(filePath string) ([]HelmETConfig, error) {
	data := lo.Must1(os.ReadFile(filePath)) // #nosec G304 FIXME: handle path

	var configs []HelmETConfig
	if err := yaml.Unmarshal(data, &configs); err != nil {
		return nil, err
	}
	return configs, nil
}
