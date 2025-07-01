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
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"helmet.io/pkg/helm"
	. "helmet.io/pkg/testutils"
	"helmet.io/pkg/types"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var (
	basePod = v1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"my": "key"},
		},
	}
	emptySvc = v1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "service",
		},
	}
	expectedMainPod = v1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"helmet.io/chart": "main", "my": "key"},
		},
	}
	expectedMainService = v1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"dependencyLabelKey": "main"},
			Name:   "service",
		},
	}
	otherPort     = intstr.FromInt(123567)
	otherPort48   = intstr.FromInt(4848)
	otherPort49   = intstr.FromInt(4849)
	otherPort1111 = intstr.FromInt(1111)

	expectedMainNetPol = netv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "main-policy",
			Namespace: "",
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main"}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					Ports: nil,
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main"}},
						},
					},
				},
			},
			Egress: []netv1.NetworkPolicyEgressRule{

				{
					To: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main"}},
						},
					},
				},
				GetInternetRule(),

				GetKubeSystemRule(),

				/*{
					To: []netv1.NetworkPolicyPeer{
						{
							IPBlock: &netv1.IPBlock{
								CIDR: "192.168.0.1/32",
							},
						},
					},
					Ports: []netv1.NetworkPolicyPort{
						{
							Port: &port,
						},
					},
				},*/
			},
		},
	}
)

var _ = Describe("Helmet:", func() {
	var chart *Chart

	BeforeEach(func() {
		chart = NewChart("main")
		Expect(chart.Name).To(Equal("main"))
		Expect(chart.IsEmpty()).To(BeTrue())
		logrus.SetOutput(io.Discard)
	})

	When("chart has no dependencies", func() {
		var outputManifests helm.HelmManifestList

		BeforeEach(func() {
			chart.AddPod(basePod, "pod1.yaml")
			chart.AddService(emptySvc, "svc.yaml")
			var err error
			outputManifests, _, _, err = SecureWholeChartFromList(
				getDefaultHelmet(chart.Build()), mockClient(), "/tmp")
			Expect(err).To(BeNil())
		})

		It("has the correct number of manifests", func() {
			Expect(len(lo.Keys(outputManifests))).To(Equal(3))
		})

		It("produces the correct manifests", func() {
			expectedNames := []string{"main/templates/pod1.yaml", "main/templates/svc.yaml", "main--netpol.yaml"}

			for _, name := range expectedNames {
				_, ok := outputManifests[name]
				Expect(ok).To(BeTrue(), "Manifest %s not found %v", name, lo.Keys(outputManifests))
			}

		})

		It("manifests have the correct content", func() {
			podManifest := outputManifests["main/templates/pod1.yaml"]

			Expect(ToPod(string(lo.Must1(yaml.Marshal(podManifest))))).To(Equal(expectedMainPod))
			svcManifest := outputManifests["main/templates/svc.yaml"]
			Expect(ToSvc(string(lo.Must1(yaml.Marshal(svcManifest))))).To(Equal(expectedMainService))
			netpolManifest := outputManifests["main--netpol.yaml"]

			netPol := ToNetworkPolicy(string(lo.Must1(yaml.Marshal(netpolManifest))))

			netPol.Spec.Egress = helm.SortEgressPolicies(netPol.Spec.Egress)

			Expect(expectedMainNetPol).To(Equal(netPol))

		})
	})

	When("chart has 1 dependency", func() {
		var outputManifests helm.HelmManifestList

		BeforeEach(func() {
			chart.AddPod(basePod, "pod.yaml")
			chart.AddService(emptySvc, "svc.yaml")
			dependency := NewChart("dep")
			dependency.AddPod(basePod, "pod.yaml")
			dependency.AddService(v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Name: "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     123567,
						},
					},
				},
			}, "svc.yaml")
			chart.AddDependency(*dependency)

			var err error
			outputManifests, _, _, err = SecureWholeChartFromList(
				getDefaultHelmet(chart.Build()), mockClient(), "/tmp")
			Expect(err).To(BeNil())
		})

		It("has the correct number of manifests", func() {
			Expect(len(lo.Keys(outputManifests))).To(Equal(6))
		})

		It("produces the correct manifests", func() {
			expectedNames := []string{
				"main/templates/pod.yaml",
				"main/templates/svc.yaml",
				"main--netpol.yaml",
				"main_dep--netpol.yaml",
				"main/charts/dep/templates/pod.yaml",
				"main/charts/dep/templates/svc.yaml",
			}

			for _, name := range expectedNames {
				_, ok := outputManifests[name]
				Expect(ok).To(BeTrue(), "Manifest %s not found %v", name, lo.Keys(outputManifests))
			}

		})

		It("manifests have the correct content", func() {
			podManifest := outputManifests["main/templates/pod.yaml"]
			Expect(ToPod(string(lo.Must1(yaml.Marshal(podManifest))))).To(Equal(expectedMainPod))

			svcManifest := outputManifests["main/templates/svc.yaml"]
			Expect(ToSvc(string(lo.Must1(yaml.Marshal(svcManifest))))).To(Equal(expectedMainService))

			expectedDepPod := v1.Pod{
				TypeMeta: metav1.TypeMeta{Kind: "Pod"},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"helmet.io/chart": "main_dep", "my": "key"},
				},
			}

			dependencyPodManifest := outputManifests["main/charts/dep/templates/pod.yaml"]
			Expect(ToPod(string(lo.Must1(yaml.Marshal(dependencyPodManifest))))).To(Equal(expectedDepPod))

			expectedDependencyService := v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"dependencyLabelKey": "main_dep"},
					Name:   "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     123567,
						},
					},
				},
			}
			dependencySvcManifest := outputManifests["main/charts/dep/templates/svc.yaml"]
			Expect(ToSvc(string(lo.Must1(yaml.Marshal(dependencySvcManifest))))).To(Equal(expectedDependencyService))
		})

		It("main network policy allows reaching the dependency", func() {
			netpolManifest := outputManifests["main--netpol.yaml"]
			proto := v1.ProtocolTCP
			updated_main_pol := netv1.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "networking.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "main-policy",
					Namespace: "",
				},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{
						{
							Ports: nil,
							From: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main"}},
								},
							},
						},
					},
					Egress: []netv1.NetworkPolicyEgressRule{

						{
							To: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main"}},
								},
							},
						},
						{
							To: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main_dep"}},
								},
							},
							Ports: []netv1.NetworkPolicyPort{
								{
									Port:     &otherPort,
									Protocol: &proto,
								},
							},
						},
						GetInternetRule(),

						GetKubeSystemRule(),

						/*{
							To: []netv1.NetworkPolicyPeer{
								{
									IPBlock: &netv1.IPBlock{
										CIDR: "192.168.0.1/32",
									},
								},
							},
							Ports: []netv1.NetworkPolicyPort{
								{
									Port: &port,
								},
							},
						},*/
					},
				},
			}
			netPol := ToNetworkPolicy(string(lo.Must1(yaml.Marshal(netpolManifest))))

			netPol.Spec.Egress = helm.SortEgressPolicies(netPol.Spec.Egress)

			netPol.Spec.Ingress = helm.SortIngressPolicies(netPol.Spec.Ingress)

			Expect(updated_main_pol).To(Equal(netPol))

		})
	})

	When("chart has multiple dependencies", func() {
		var outputManifests helm.HelmManifestList

		BeforeEach(func() {
			chart.AddPod(basePod, "pod.yaml")
			chart.AddService(v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Name: "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     1111,
						},
					},
				},
			}, "svc.yaml")
			dependencyA := NewChart("depA")
			dependencyA.AddPod(basePod, "pod.yaml")
			dependencyA.AddService(v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Name: "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     123567,
						},
					},
				},
			}, "svc.yaml")
			chart.AddDependency(*dependencyA)

			dependencyB := NewChart("depB")
			dependencyB.AddPod(basePod, "pod.yaml")
			dependencyB.AddService(v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Name: "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     4848,
						},
					},
				},
			}, "svc.yaml")
			chart.AddDependency(*dependencyB)

			dependencyC := NewChart("depC")
			dependencyC.AddPod(basePod, "pod.yaml")
			dependencyC.AddService(v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Name: "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     4849,
						},
					},
				},
			}, "svc.yaml")
			chart.AddDependency(*dependencyC)

			var err error
			outputManifests, _, _, err = SecureWholeChartFromList(
				getDefaultHelmet(chart.Build()), mockClient(), "/tmp")
			Expect(err).To(BeNil())
		})

		It("has the correct number of manifests", func() {
			Expect(len(lo.Keys(outputManifests))).To(Equal(12))
		})

		It("produces the correct manifests", func() {
			expectedNames := []string{
				"main/templates/pod.yaml",
				"main/templates/svc.yaml",
				"main--netpol.yaml",
				"main_depA--netpol.yaml",
				"main/charts/depA/templates/pod.yaml",
				"main/charts/depA/templates/svc.yaml",
				"main_depB--netpol.yaml",
				"main/charts/depB/templates/pod.yaml",
				"main/charts/depB/templates/svc.yaml",
				"main_depC--netpol.yaml",
				"main/charts/depC/templates/pod.yaml",
				"main/charts/depC/templates/svc.yaml",
			}

			for _, name := range expectedNames {
				_, ok := outputManifests[name]
				Expect(ok).To(BeTrue(), "Manifest %s not found %v", name, lo.Keys(outputManifests))
			}

		})

		It("manifests have the correct content", func() {
			podManifest := outputManifests["main/templates/pod.yaml"]
			Expect(ToPod(string(lo.Must1(yaml.Marshal(podManifest))))).To(Equal(expectedMainPod))

			expectedMainServiceWithPort := v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"dependencyLabelKey": "main"},
					Name:   "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     1111,
						},
					},
				},
			}

			svcManifest := outputManifests["main/templates/svc.yaml"]
			Expect(ToSvc(string(lo.Must1(yaml.Marshal(svcManifest))))).To(Equal(expectedMainServiceWithPort))

			expectedDepAPod := v1.Pod{
				TypeMeta: metav1.TypeMeta{Kind: "Pod"},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"helmet.io/chart": "main_depA", "my": "key"},
				},
			}

			dependencyAPodManifest := outputManifests["main/charts/depA/templates/pod.yaml"]
			Expect(ToPod(string(lo.Must1(yaml.Marshal(dependencyAPodManifest))))).To(Equal(expectedDepAPod))

			expectedDependencyAService := v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"dependencyLabelKey": "main_depA"},
					Name:   "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     123567,
						},
					},
				},
			}
			dependencyASvcManifest := outputManifests["main/charts/depA/templates/svc.yaml"]
			Expect(ToSvc(string(lo.Must1(yaml.Marshal(dependencyASvcManifest))))).To(Equal(expectedDependencyAService))

			expectedDepBPod := v1.Pod{
				TypeMeta: metav1.TypeMeta{Kind: "Pod"},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"helmet.io/chart": "main_depB", "my": "key"},
				},
			}

			dependencyBPodManifest := outputManifests["main/charts/depB/templates/pod.yaml"]
			Expect(ToPod(string(lo.Must1(yaml.Marshal(dependencyBPodManifest))))).To(Equal(expectedDepBPod))

			expectedDependencyBService := v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"dependencyLabelKey": "main_depB"},
					Name:   "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     4848,
						},
					},
				},
			}
			dependencyBSvcManifest := outputManifests["main/charts/depB/templates/svc.yaml"]
			Expect(ToSvc(string(lo.Must1(yaml.Marshal(dependencyBSvcManifest))))).To(Equal(expectedDependencyBService))

			expectedDepCPod := v1.Pod{
				TypeMeta: metav1.TypeMeta{Kind: "Pod"},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"helmet.io/chart": "main_depC", "my": "key"},
				},
			}

			dependencyCPodManifest := outputManifests["main/charts/depC/templates/pod.yaml"]
			Expect(ToPod(string(lo.Must1(yaml.Marshal(dependencyCPodManifest))))).To(Equal(expectedDepCPod))

			expectedDependencyCService := v1.Service{
				TypeMeta: metav1.TypeMeta{Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"dependencyLabelKey": "main_depC"},
					Name:   "service",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     4849,
						},
					},
				},
			}
			dependencyCSvcManifest := outputManifests["main/charts/depC/templates/svc.yaml"]
			Expect(ToSvc(string(lo.Must1(yaml.Marshal(dependencyCSvcManifest))))).To(Equal(expectedDependencyCService))
		})

		It("main network policy allows reaching the dependencies", func() {
			netpolManifest := outputManifests["main--netpol.yaml"]
			proto := v1.ProtocolTCP
			updated_main_pol := netv1.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "networking.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "main-policy",
					Namespace: "",
				},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{
						{
							Ports: nil,
							From: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main"}},
								},
							},
						},
						{
							Ports: []netv1.NetworkPolicyPort{
								{
									Port:     &otherPort1111,
									Protocol: &proto,
								},
							},
							From: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: nil},
								},
							},
						},
					},
					Egress: []netv1.NetworkPolicyEgressRule{

						{
							To: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main"}},
								},
							},
							Ports: nil,
						},
						{
							To: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main_depA"}},
								},
							},
							Ports: []netv1.NetworkPolicyPort{
								{
									Port:     &otherPort,
									Protocol: &proto,
								},
							},
						},
						{
							To: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main_depB"}},
								},
							},
							Ports: []netv1.NetworkPolicyPort{
								{
									Port:     &otherPort48,
									Protocol: &proto,
								},
							},
						},
						{
							To: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main_depC"}},
								},
							},
							Ports: []netv1.NetworkPolicyPort{
								{
									Port:     &otherPort49,
									Protocol: &proto,
								},
							},
						},
						GetInternetRule(),

						GetKubeSystemRule(),

						/*{
							To: []netv1.NetworkPolicyPeer{
								{
									IPBlock: &netv1.IPBlock{
										CIDR: "192.168.0.1/32",
									},
								},
							},
							Ports: []netv1.NetworkPolicyPort{
								{
									Port: &port,
								},
							},
						},*/
					},
				},
			}
			netPol := ToNetworkPolicy(string(lo.Must1(yaml.Marshal(netpolManifest))))

			netPol.Spec.Egress = helm.SortEgressPolicies(netPol.Spec.Egress)
			log.Info(netPol.Spec.Egress)
			netPol.Spec.Ingress = helm.SortIngressPolicies(netPol.Spec.Ingress)
			Expect(updated_main_pol).To(Equal(netPol))

		})

		It("a dependency cannot reach main or other dependencies", func() {
			netpolManifest := outputManifests["main_depA--netpol.yaml"]
			proto := v1.ProtocolTCP
			updated_main_pol := netv1.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "networking.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "main--depA-policy",
					Namespace: "",
				},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main_depA"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{
						{
							Ports: []netv1.NetworkPolicyPort{
								{
									Port:     &otherPort,
									Protocol: &proto,
								},
							},
							From: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"helmet.io/chart": "main"}},
								},
							},
						},
						{
							Ports: nil,
							From: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"helmet.io/chart": "main_depA"},
									},
								},
							},
						},
					},
					Egress: []netv1.NetworkPolicyEgressRule{

						{
							To: []netv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "main_depA"}},
								},
							},
							Ports: nil,
						},
						GetInternetRule(),

						GetKubeSystemRule(),

						/*{
							To: []netv1.NetworkPolicyPeer{
								{
									IPBlock: &netv1.IPBlock{
										CIDR: "192.168.0.1/32",
									},
								},
							},
							Ports: []netv1.NetworkPolicyPort{
								{
									Port: &port,
								},
							},
						},*/
					},
				},
			}
			netPol := ToNetworkPolicy(string(lo.Must1(yaml.Marshal(netpolManifest))))
			netPol.Spec.Egress = helm.SortEgressPolicies(netPol.Spec.Egress)
			netPol.Spec.Ingress = helm.SortIngressPolicies(netPol.Spec.Ingress)

			Expect(updated_main_pol).To(Equal(netPol))

		})

	})

})

func getDefaultHelmet(manifests helm.HelmManifestList) types.Helmet {
	return types.Helmet{
		Manifests:   manifests,
		HelmetLabel: "dependencyLabelKey",
	}
}
