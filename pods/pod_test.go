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
package pods

import (
	"encoding/json"
	"testing"

	"github.com/samber/lo"
	"helmet.io/pkg/helm"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "helmet.io/pkg/testutils"
)

func TestPods(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Pods suite")
}

var _ = Describe("createPolicy", func() {
	It("Creates a correct policy", func() {
		expectedPolicy := netv1.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "NetworkPolicy",
				APIVersion: "networking.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-policy-policy",
				Namespace: "",
			},
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},

				Egress: []netv1.NetworkPolicyEgressRule{
					GetInternetRule(),

					GetKubeSystemRule(),
				},
			},
		}

		podSelector := metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}

		result := lo.Must1(json.Marshal(createPolicy(podSelector, "my-policy", nil, nil)))

		var netpol netv1.NetworkPolicy

		err := json.Unmarshal(result, &netpol)
		Expect(err).ToNot(HaveOccurred())

		Expect(createPolicy(podSelector, "my-policy", nil, nil)).To(Equal(expectedPolicy))
	})
})

var _ = Describe("AddWrapperLabelToPods", func() {
	It("Adds label to pods", func() {
		manifests := helm.HelmManifestList{
			"mychart/templates/abc.yaml": helm.HelmManifest{
				"kind":     "Pod",
				"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"my": "key"}},
			},
			"mychart/templates/svc.yaml": helm.HelmManifest{"bar": 2},
		}
		expectedManifests := helm.HelmManifestList{
			"mychart/templates/abc.yaml": {
				"kind":     "Pod",
				"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"my": "key", "key": "mychart"}},
			},
			"mychart/templates/svc.yaml": {"bar": 2},
		}

		AddWrapperLabelToPods(manifests, "key")

		Expect(lo.Must1(json.Marshal(manifests))).To(Equal(lo.Must1(json.Marshal(expectedManifests))))
	})
})

var _ = Describe("BuildNetworkPolicyForPods", func() {
	It("Creates a correct policy", func() {
		expectedPolicy := netv1.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "NetworkPolicy",
				APIVersion: "networking.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "myPolicy-policy",
				Namespace: "",
			},
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress},

				Egress: []netv1.NetworkPolicyEgressRule{
					GetInternetRule(),

					GetKubeSystemRule(),
				},
				Ingress: nil,
			},
		}

		podSelector := metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}

		Expect(ToNetworkPolicy(BuildNetworkPolicyForPods(podSelector, "myPolicy", []netv1.NetworkPolicyEgressRule{}, []netv1.NetworkPolicyIngressRule{}))).To(Equal(expectedPolicy))
	})
})

var _ = Describe("SetLabelValue", func() {
	It("Sets the label when metadata and labels are available", func() {
		manifest := helm.HelmManifest{
			"kind":     "Pod",
			"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"my": "key"}},
		}
		expectedManifest := helm.HelmManifest{
			"kind":     "Pod",
			"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"my": "key", "key": "value"}},
		}

		result := SetLabelValue(manifest, PODS_LABEL["Pod"], "key", "value")

		Expect(lo.Must1(json.Marshal(result))).To(Equal(lo.Must1(json.Marshal(expectedManifest))))
	})

	It("Sets the label when only metadata is available", func() {
		manifest := helm.HelmManifest{
			"kind":     "Pod",
			"metadata": helm.HelmManifest{},
		}
		expectedManifest := helm.HelmManifest{
			"kind":     "Pod",
			"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"key": "value"}},
		}

		result := SetLabelValue(manifest, PODS_LABEL["Pod"], "key", "value")

		Expect(lo.Must1(json.Marshal(result))).To(Equal(lo.Must1(json.Marshal(expectedManifest))))
	})

	It("Sets the label when nothing available", func() {
		manifest := helm.HelmManifest{"kind": "Pod"}
		expectedManifest := helm.HelmManifest{
			"kind":     "Pod",
			"metadata": helm.HelmManifest{"labels": helm.HelmManifest{"key": "value"}},
		}

		result := SetLabelValue(manifest, PODS_LABEL["Pod"], "key", "value")

		Expect(lo.Must1(json.Marshal(result))).To(Equal(lo.Must1(json.Marshal(expectedManifest))))
	})
})
