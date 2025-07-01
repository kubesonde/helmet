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
	"os"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
	"helmet.io/pkg/helm"
	"helmet.io/pkg/pods"
	"helmet.io/pkg/testutils"
	"helmet.io/pkg/types"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	testclient "k8s.io/client-go/kubernetes/fake"
)

func mockClient() kubernetes.Interface {
	client := testclient.NewSimpleClientset()

	endpoint := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubernetes",
		},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{
				IP: "192.168.0.1",
			}},
			Ports: []v1.EndpointPort{{
				Port: 8080,
			}},
		}},
	}

	lo.Must(client.CoreV1().Endpoints("default").Create(context.TODO(), endpoint, metav1.CreateOptions{}))
	return client

}

func Test_writeManifestList(t *testing.T) {
	tmpDir := t.TempDir()
	manifestList := helm.HelmManifestList{
		"mychart/templates/abc.yaml":  {"kind": "foo"},
		"mychart/templates/svc.yaml":  {"kind": "Service", "metadata": helm.HelmManifest{"labels": helm.HelmManifest{"label/key": "value"}}},
		"mychart/templates/svc2.yaml": {"kind": "Service", "metadata": helm.HelmManifest{"labels": helm.HelmManifest{"label/svc": "template"}}},
	}
	lo.Must0(WriteManifestList(manifestList, tmpDir))
	path := tmpDir + "/mychart_templates_abc.yaml"
	_, err := os.Stat(path)
	if err != nil {
		t.Errorf("Path does not exist %s", path)
	}
}

func TestFilterDependencyDescendant(t *testing.T) {
	dep := []string{"wordpress_mariadb_dep",
		"wordpress_mariadb",
		"wordpress_postgresql",
		"wordpress"}
	descendant := FilterDependencyDescendant(dep, "wordpress")
	assert.Equal(t, dep, descendant)
	descendant = FilterDependencyDescendant(dep, "wordpress_mariadb")
	assert.Equal(t, []string{"wordpress_mariadb_dep",
		"wordpress_mariadb"}, descendant)
	descendant = FilterDependencyDescendant(dep, "wordpress_mariadb_dep")
	assert.Equal(t, []string{"wordpress_mariadb_dep"}, descendant)
	descendant = FilterDependencyDescendant(dep, "redis")
	var empty []string
	assert.Equal(t, empty, descendant)
}

func TestFilterDependencyAncestor(t *testing.T) {
	dep := []string{"wordpress_mariadb_dep",
		"wordpress_mariadb",
		"wordpress_postgresql",
		"wordpress"}
	descendant := FilterDependencyAncestor(dep, "wordpress")
	var empty []string
	assert.Equal(t, empty, descendant)
	descendant = FilterDependencyAncestor(dep, "wordpress_mariadb")
	assert.Equal(t, []string{"wordpress"}, descendant)
	descendant = FilterDependencyAncestor(dep, "wordpress_mariadb_dep")
	assert.Equal(t, []string{
		"wordpress_mariadb",
		"wordpress"}, descendant)
	descendant = FilterDependencyAncestor(dep, "redis")

	assert.Equal(t, empty, descendant)
}

func TestAddLabelsMainChart(t *testing.T) {

	expectedPod := v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"helmet.io/chart": "main", "my": "key"},
		},
	}
	chart := testutils.NewChart("main")
	chart.AddPod(v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"my": "key"},
		},
	}, "pod1.yaml")
	manifests := chart.Build()

	pods.AddWrapperLabelToPods(manifests, HelmetPodLabel)
	podManifestBytes := lo.Must1(yaml.Marshal(manifests["main/templates/pod1.yaml"]))

	assert.Equal(t, expectedPod, testutils.ToPod(string(podManifestBytes)))

}

func TestSecureMainChart(t *testing.T) {

	expected_policy := netv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-release-policy",
			Namespace: "",
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					Ports: nil,
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "my-release"}},
						},
					},
				},
			},
			Egress: []netv1.NetworkPolicyEgressRule{
				{
					To: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "my-release"}},
						},
					},
				},
				testutils.GetInternetRule(),

				testutils.GetKubeSystemRule(),
			},
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "my-release"}},
		},
	}

	preNetPol := prepareNetworkPolicy("192.168.0.1", 8080)
	manifestList := map[string]helm.HelmManifestList{
		"dep1": {
			"mychart/templates/abc.yaml":  {"kind": "foo"},
			"mychart/templates/svc.yaml":  {"kind": "Service", "metadata": helm.HelmManifest{"labels": helm.HelmManifest{"label/key": "value"}}},
			"mychart/templates/svc2.yaml": {"kind": "Service", "metadata": helm.HelmManifest{"labels": helm.HelmManifest{"label/svc": "template"}}},
		},
	}
	netpol := preNetPol("my-release", manifestList, manifestList, manifestList, false)

	pol := testutils.ToNetworkPolicy(netpol)
	pol.Spec.Egress = helm.SortEgressPolicies(pol.Spec.Egress)
	pol.Spec.Ingress = helm.SortIngressPolicies(pol.Spec.Ingress)
	assert.Equal(t, expected_policy, pol)
}

func TestSecureDependencyPods(t *testing.T) {
	expected_policy := netv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mydep-policy",
			Namespace: "",
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					Ports: nil,
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "mydep"}},
						},
					},
				},
			},
			Egress: []netv1.NetworkPolicyEgressRule{
				{
					To: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "mydep"}},
						},
					},
				},
				testutils.GetInternetRule(),

				testutils.GetKubeSystemRule(),
			},
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "mydep"}},
		},
	}
	chart := testutils.NewChart("main")
	chart.AddPod(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"my": "key"},
		},
	}, "pod1.yaml")
	chart.AddService(v1.Service{}, "svc.yaml")

	netpol := prepareNetworkPolicy("192.168.0.1", 8080)
	pol := testutils.ToNetworkPolicy(netpol("mydep", map[string]helm.HelmManifestList{"mydep": {}}, map[string]helm.HelmManifestList{"mydep": {}}, map[string]helm.HelmManifestList{"mydep": {}}, false))
	pol.Spec.Egress = helm.SortEgressPolicies(pol.Spec.Egress)

	assert.Equal(t, expected_policy, pol)
}

func TestComputeNetworkPoliciesForDependencies(t *testing.T) {
	expected_policy := netv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mydep-policy",
			Namespace: "",
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					Ports: nil,
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "mydep"}},
						},
					},
				},
			},
			Egress: []netv1.NetworkPolicyEgressRule{
				testutils.GetInternetRule(),
				{
					To: []netv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "mydep"}},
						},
					},
				},
				testutils.GetKubeSystemRule(),
			},
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"helmet.io/chart": "mydep"}},
		},
	}
	chart := testutils.NewChart("main")
	chart.AddPod(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"my": "key"},
		},
	}, "pod1.yaml")
	chart.AddService(v1.Service{}, "svc.yaml")

	netpol := prepareNetworkPolicy("192.168.0.1", 8080)

	dependency := testutils.NewChart("dependency")
	dependency.AddPod(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"my": "key"},
		},
	}, "mydep.yaml")
	retValue := computeNetworkPoliciesForDependencies(map[string]helm.HelmManifestList{"mydep": dependency.Build()},
		netpol)
	netPol := testutils.ToNetworkPolicy(string(lo.Must1(yaml.Marshal(retValue[0].Value))))
	sortedEgressPol := helm.SortEgressPolicies(netPol.Spec.Egress)
	netPol.Spec.Egress = sortedEgressPol

	sortedEgressPol = helm.SortEgressPolicies(expected_policy.Spec.Egress)
	expected_policy.Spec.Egress = sortedEgressPol
	assert.Equal(t, expected_policy, netPol)

}

func Test_SecureWholeChart(t *testing.T) {

	expected_entries := []string{"mychart_dependency--netpol.yaml",
		"mychart/charts/dependency/templates/mydep.yaml",
		"mychart/templates/abc.yaml",
		"mychart--netpol.yaml"}
	dependency := testutils.NewChart("dependency")
	dependency.AddPod(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"my": "key"},
		},
	}, "mydep.yaml")
	mainChart := testutils.NewChart("mychart")
	mainChart.AddPod(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"other": "key"},
		},
	}, "abc.yaml")
	mainChart.AddDependency(*dependency)
	manifests := mainChart.Build()
	hw := types.Helmet{
		Manifests:   manifests,
		HelmetLabel: "dependencyLabelKey",
	}

	retval, _, _, err := SecureWholeChartFromList(hw, mockClient(), t.TempDir())

	if err != nil {
		assert.Nilf(t, err, "Error while executing test: %s", err.Error())
	}

	for _, value := range expected_entries {

		val, ok := retval[value]

		assert.Equal(t, ok, true, "Chart for %s not found", value)
		assert.NotNilf(t, val, "Chart for %s is empty", value)
	}
}

func Test_MultipleServices(t *testing.T) {

	expected_entries := []string{"mychart_dependency--netpol.yaml",
		"mychart/charts/dependency/templates/pod1.yaml",
		"mychart/charts/dependency/templates/pod2.yaml",
		"mychart/charts/dependency/templates/svc.yaml",

		"mychart/templates/mainpod.yaml",
		"mychart--netpol.yaml"}

	dependency := testutils.NewChart("dependency")
	dependency.AddPod(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"pod": "dependencypod1"},
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				v1.Container{
					Name:  "testcontainer",
					Image: "docker.io/myimage",
					Ports: []v1.ContainerPort{
						v1.ContainerPort{ContainerPort: 8080},
					},
				},
			},
		},
	}, "pod1.yaml")
	dependency.AddPod(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"pod": "dependencypod2"},
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				v1.Container{
					Name:  "testcontainer",
					Image: "docker.io/myimage",
					Ports: []v1.ContainerPort{
						v1.ContainerPort{ContainerPort: 8080},
					},
				},
			},
		},
	}, "pod2.yaml")
	dependency.AddService(v1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind: "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"service": "service1"},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{{
				Port:       80,
				TargetPort: intstr.FromInt(8080),
			}},
			Selector: map[string]string{"pod": "dependencypod1"},
		},
	}, "svc.yaml")

	mainChart := testutils.NewChart("mychart")
	mainChart.AddPod(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"pod": "mainpod"},
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
	}, "mainpod.yaml")
	mainChart.AddDependency(*dependency)
	manifests := mainChart.Build()
	hw := types.Helmet{
		Manifests:   manifests,
		HelmetLabel: "dependencyLabelKey",
	}

	retval, _, _, err := SecureWholeChartFromList(hw, mockClient(), t.TempDir())

	if err != nil {
		assert.Nilf(t, err, "Error while executing test: %s", err.Error())
	}

	for _, value := range expected_entries {

		val, ok := retval[value]

		assert.Equal(t, ok, true, "Chart for %s not found", value)
		assert.NotNilf(t, val, "Chart for %s is empty", value)
	}

}
