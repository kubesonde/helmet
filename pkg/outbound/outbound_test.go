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
	"sort"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"helmet.io/pkg/helm"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestOutbound(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Outbound suite")
}

var manifestList = helm.HelmManifestList{
	"mychart/templates/abc.yaml": {"kind": "foo"},
	"mychart/templates/svc.yaml": {
		"kind":     "Service",
		"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"label/key": "value"}, "name": "test-service"},
		"spec": helm.HelmManifest{
			"selector": helm.HelmManifest{"label/key": "value"},
			"ports":    []helm.HelmManifest{{"protocol": "TCP", "port": 80, "targetPort": 8080}},
		},
	},
	"mychart/templates/svc2.yaml": {
		"kind":     "Service",
		"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"label/svc": "template", "name": "test-service2"}},
		"spec": helm.HelmManifest{
			"selector": helm.HelmManifest{"label/svc": "template"},
			"ports":    []helm.HelmManifest{{"protocol": "TCP", "port": 90, "targetPort": 8443}, {"protocol": "TCP", "port": 91, "targetPort": 8443}},
		},
	},
}

var _ = Describe("AddLabelToServices", func() {
	It("Adds a Label to the service if it is not present", func() {
		newManifesList, _ := AddLabelToServices(manifestList, "label/svc", "template")

		Expect(lo.Keys(newManifesList["mychart/templates/abc.yaml"])).To(HaveLen(1))
		Expect(newManifesList["mychart/templates/abc.yaml"]).To(Equal(helm.HelmManifest{"kind": "foo"}))

		Expect(lo.Keys(newManifesList["mychart/templates/svc.yaml"]["metadata"].(helm.HelmManifest)["labels"].(helm.HelmManifest))).To(HaveLen(2))
		Expect(newManifesList["mychart/templates/svc.yaml"]["metadata"].(helm.HelmManifest)["labels"].(helm.HelmManifest)["label/svc"]).To(Equal("template"))

		Expect(lo.Keys(newManifesList["mychart/templates/svc2.yaml"]["metadata"].(helm.HelmManifest)["labels"].(helm.HelmManifest))).To(HaveLen(2))
		Expect(newManifesList["mychart/templates/svc.yaml"]["metadata"].(helm.HelmManifest)["labels"].(helm.HelmManifest)["label/svc"]).To(Equal("template"))
	})
	It("Returns the same chart if no services are available", func() {
		manifest := helm.HelmManifestList{
			"mychart/templates/abc.yaml":  {"kind": "foo"},
			"mychart/templates/abcd.yaml": {"kind": "Secret"},
		}

		newManifesList, _ := AddLabelToServices(manifest, "label/svc", "template")

		Expect(manifest).To(Equal(newManifesList))
	})
})

func Test_DependencyRelation(t *testing.T) {
	manifestList := helm.HelmManifestList{
		"mychart/templates/svc.yaml":  {"kind": "Service", "metadata": helm.HelmManifest{"labels": helm.HelmManifest{"app.kubernetes.io/part-of": "value"}}},
		"mychart/templates/svc2.yaml": {"kind": "Service", "metadata": helm.HelmManifest{"labels": helm.HelmManifest{"app.kubernetes.io/part-of": "template"}}},
	}

	result := DependencyRelation(manifestList)
	sort.Strings(result)

	assert.Equal(t, []string{"template", "value"}, result)
}

var _ = Describe("DependencyRelation", func() {
	It("DependencyRelation", func() {
		manifestList := helm.HelmManifestList{
			"mychart/templates/svc.yaml":  {"kind": "Service", "metadata": helm.HelmManifest{"labels": helm.HelmManifest{"app.kubernetes.io/part-of": "value"}}},
			"mychart/templates/svc2.yaml": {"kind": "Service", "metadata": helm.HelmManifest{"labels": helm.HelmManifest{"app.kubernetes.io/part-of": "template"}}},
		}

		result := DependencyRelation(manifestList)
		sort.Strings(result)

		Expect(result).To(Equal([]string{"template", "value"}))
	})
})

var _ = Describe("AddLabelToDependencyServices", func() {
	It("Adds labels when services are available", func() {
		groupedManifests := map[string]helm.HelmManifestList{
			"dep1": {
				"mychart/templates/abc.yaml": {"kind": "foo"},
				"mychart/templates/svc.yaml": {
					"kind":     "Service",
					"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"label/key": "value"}, "name": "test-service"},
					"spec": helm.HelmManifest{
						"selector": helm.HelmManifest{"label/key": "value"},
						"ports":    []helm.HelmManifest{{"protocol": "TCP", "port": 80, "targetPort": 8080}},
					},
				},
			},
		}
		expectedGroupedManifests := map[string]helm.HelmManifestList{
			"dep1": {
				"mychart/templates/abc.yaml": {"kind": "foo"},
				"mychart/templates/svc.yaml": {
					"kind":     "Service",
					"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"label/key": "value", "foo": "dep1"}, "name": "test-service"},
					"spec": helm.HelmManifest{
						"selector": helm.HelmManifest{"label/key": "value"},
						"ports":    []helm.HelmManifest{{"protocol": "TCP", "port": 80, "targetPort": 8080}},
					},
				},
			},
		}
		result := AddLabelToDependencyServices(groupedManifests, "foo")
		Expect(lo.Keys(result)).To(HaveLen(1))
		Expect(result["dep1"]).To(Equal(1))
		Expect(groupedManifests).To(Equal(expectedGroupedManifests))
	})
	It("Does nothing when there are no services", func() {
		groupedManifests := map[string]helm.HelmManifestList{
			"dep1": {
				"mychart/templates/abc.yaml": {"kind": "foo"},
			},
		}

		expectedGroupedManifests := map[string]helm.HelmManifestList{
			"dep1": {
				"mychart/templates/abc.yaml": {"kind": "foo"},
			},
		}

		result := AddLabelToDependencyServices(groupedManifests, "foo")
		Expect(lo.Keys(result)).To(HaveLen(1))
		Expect(result["mychart"]).To(Equal(0))
		Expect(groupedManifests).To(Equal(expectedGroupedManifests))
	})
})

func Test_AddLabelToServices(t *testing.T) {
	expectedManifest := helm.HelmManifest{
		"kind":     "Service",
		"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"label/key": "value", "helmet.io/chart": "mychart", "label/svc": "template"}, "name": "test-service"},
		"spec": helm.HelmManifest{
			"selector": helm.HelmManifest{"label/key": "value"},
			"ports":    []helm.HelmManifest{{"protocol": "TCP", "port": 80, "targetPort": 8080}},
		},
	}

	newManifestList, _ := AddLabelToServices(manifestList, "helmet.io/chart", "mychart")
	assert.Equal(t, expectedManifest, newManifestList["mychart/templates/svc.yaml"])
}

func Test_GetServices(t *testing.T) {
	assert.Len(t, GetServices(manifestList), 2, "Real length = %d", len(GetServices(manifestList)))
}

var _ = Describe("getServicesPorts", func() {
	It("works", func() {
		ports, err := getServicesPorts(manifestList)
		Expect(err).ToNot(HaveOccurred())
		Expect(ports).To(HaveLen(3))
	})
})

func TestConvertServicePortsToNetworkPolicyPort(t *testing.T) {
	servicePorts := []v1.ServicePort{
		{
			Protocol: v1.ProtocolTCP,
			Port:     8080,
		},
		{
			Protocol: v1.ProtocolUDP,
			Port:     8080,
		},
	}
	port := intstr.FromInt(8080)
	tcp := v1.ProtocolTCP
	udp := v1.ProtocolUDP
	expectedNetPolPorts := []netv1.NetworkPolicyPort{
		{
			Port:     &port,
			Protocol: &tcp,
		},
		{
			Port:     &port,
			Protocol: &udp,
		},
	}
	assert.Equal(t, expectedNetPolPorts, ConvertServicePortsToNetworkPolicyPort(servicePorts))
}

func TestConvertServicePortsToNetworkPolicyPortWhenNoProtocol(t *testing.T) {
	servicePorts := []v1.ServicePort{
		{
			Port: 8080,
		},
	}
	port := intstr.FromInt(8080)
	tcp := v1.ProtocolTCP
	expectedNetPolPorts := []netv1.NetworkPolicyPort{
		{
			Port:     &port,
			Protocol: &tcp,
		},
	}
	assert.Equal(t, expectedNetPolPorts, ConvertServicePortsToNetworkPolicyPort(servicePorts))
}

func TestConvertServicePortsToIngressNetworkPolicyPortForDebug(t *testing.T) {
	servicePorts := []v1.ServicePort{
		{
			Port: 8080,
		},
		{
			Name:       "name",
			Port:       5432,
			TargetPort: intstr.FromString("tcpPosgresql"),
		},
		{
			Name:       "name1",
			Port:       5433,
			TargetPort: intstr.FromInt(5555),
		},
	}
	port := intstr.FromInt(8080)
	port5432 := intstr.FromInt(5432)
	port5433 := intstr.FromInt(5433)
	port5555 := intstr.FromInt(5555)
	portSQL := intstr.FromString("tcpPosgresql")
	tcp := v1.ProtocolTCP
	expectedNetPolPorts := []netv1.NetworkPolicyPort{
		{
			Port:     &port,
			Protocol: &tcp,
		},
		{
			Port:     &port5432,
			Protocol: &tcp,
		},
		{
			Port:     &port5555,
			Protocol: &tcp,
		},
		{
			Port:     &port5433,
			Protocol: &tcp,
		},
		{
			Port:     &portSQL,
			Protocol: &tcp,
		},
	}

	assert.Equal(t, helm.SortNetPolPorts(expectedNetPolPorts), helm.SortNetPolPorts(ConvertServicePortsToIngressNetworkPolicyPortForDebug(servicePorts)))
}
