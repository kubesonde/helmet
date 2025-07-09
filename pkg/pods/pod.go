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
	"bytes"
	"fmt"
	"reflect"
	"strings"

	"github.com/samber/lo"
	logf "github.com/sirupsen/logrus"
	"helmet.io/pkg/helm"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/cli-runtime/pkg/printers"
)

var (
	log = logf.WithFields(logf.Fields{
		"package": "pods",
	})

	toKubeSystemNS netv1.NetworkPolicyPeer = netv1.NetworkPolicyPeer{
		NamespaceSelector: &v1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
		},
	}
	toAllNonPrivateAddresses netv1.NetworkPolicyPeer = netv1.NetworkPolicyPeer{
		IPBlock: &netv1.IPBlock{
			CIDR:   "0.0.0.0/0",
			Except: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
	}

	port       = intstr.FromInt(53)
	protoUDP   = corev1.ProtocolUDP
	protoTCP   = corev1.ProtocolTCP
	DNSuDPpOrt = netv1.NetworkPolicyPort{
		Port:     &port,
		Protocol: &protoUDP,
	}
	DNStCPpOrt = netv1.NetworkPolicyPort{
		Port:     &port,
		Protocol: &protoTCP,
	}

	PODS_LABEL = map[string][]string{
		"Pod":         {"metadata", "labels"},
		"Job":         {"spec", "template", "metadata", "labels"},
		"Cronjob":     {"spec", "jobTemplate", "spec", "template", "metadata", "labels"},
		"DaemonSet":   {"spec", "template", "metadata", "labels"},
		"StatefulSet": {"spec", "template", "metadata", "labels"},
		"Deployment":  {"spec", "template", "metadata", "labels"},
	}
	PODS_CONTAINER = map[string][]string{
		"Pod":         {"spec", "containers"},
		"Job":         {"spec", "template", "spec", "containers"},
		"Cronjob":     {"spec", "jobTemplate", "spec", "template", "spec", "containers"},
		"DaemonSet":   {"spec", "template", "spec", "containers"},
		"StatefulSet": {"spec", "template", "spec", "containers"},
		"Deployment":  {"spec", "template", "spec", "containers"},
	}
	PODS_KIND = lo.Keys(PODS_LABEL)
)

func init() {
	logf.SetFormatter(&logf.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
}

func createPolicy(podSelector v1.LabelSelector, policyName string, egress []netv1.NetworkPolicyEgressRule, ingress []netv1.NetworkPolicyIngressRule) netv1.NetworkPolicy {
	default_rules := []netv1.NetworkPolicyEgressRule{
		{
			To: []netv1.NetworkPolicyPeer{toAllNonPrivateAddresses},
		},
		{
			To:    []netv1.NetworkPolicyPeer{toKubeSystemNS},
			Ports: []netv1.NetworkPolicyPort{DNSuDPpOrt, DNStCPpOrt},
		},
	}
	netPol := netv1.NetworkPolicy{
		TypeMeta: v1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: fmt.Sprintf("%s-policy", policyName),
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: podSelector,
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			Egress:      append(default_rules, egress...),
		},
	}
	if ingress != nil {
		netPol.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress}
		netPol.Spec.Ingress = ingress
	}
	return netPol
}

func BuildNetworkPolicyForPods(labelSelector v1.LabelSelector, policyName string, egress []netv1.NetworkPolicyEgressRule, ingress []netv1.NetworkPolicyIngressRule) string {
	validPolicyName := strings.ReplaceAll(policyName, "_", "--")
	policy := createPolicy(labelSelector, validPolicyName, egress, ingress)

	y := printers.YAMLPrinter{}
	buf := new(bytes.Buffer)
	lo.Must0(y.PrintObj(&policy, buf))
	resource := buf.String()

	return strings.Trim(strings.Trim(strings.ReplaceAll(resource, "status: {}", ""), "\n"), " ")
}

func copyManifest(input helm.HelmManifest) helm.HelmManifest {
	return reflect.ValueOf(input).Interface().(helm.HelmManifest)
}

func SetLabelValue(manifest helm.HelmManifest, labelChain []string, labelKey string, labelValue string) helm.HelmManifest {
	if len(labelChain) == 0 {
		return manifest
	}
	output_manifest := copyManifest(manifest)

	pointerToLabels := output_manifest
	lo.ForEach(labelChain, func(item string, index int) {
		if chainLinkManifest, ok := pointerToLabels[item].(helm.HelmManifest); ok {
			pointerToLabels = chainLinkManifest
		} else if chainLinkMap, ok := pointerToLabels[item].(map[string]interface{}); ok {
			pointerToLabels = chainLinkMap
		} else {
			pointerToLabels[item] = helm.HelmManifest{}
			pointerToLabels = pointerToLabels[item].(helm.HelmManifest)
		}
	})
	pointerToLabels[labelKey] = labelValue

	return output_manifest
}

func GetComputeUnits(manifestList helm.HelmManifestList) helm.HelmManifestList {
	updatedList := helm.HelmManifestList{}
	for key, res := range manifestList {
		value, ok := res["kind"]
		if ok {
			_, ok := lo.Find(PODS_KIND, func(i string) bool { return i == value })
			if ok {
				updatedList[key] = res
			}
		}
	}
	return updatedList
}

func AddWrapperLabelToPods(manifestList helm.HelmManifestList, labelKey string) {
	result := lo.Filter(lo.Map(lo.Values(manifestList), func(value helm.HelmManifest, index int) string {
		if value["kind"] == nil {
			return ""
		}
		return value["kind"].(string)
	}), func(item string, i int) bool {
		return lo.Contains(PODS_KIND, item)
	})
	log.WithField("kinds", result).WithField("app", labelKey).Infof("Found %d manifest(s) with pods", len(result))
	for key, res := range manifestList {
		value, ok := res["kind"]
		if ok {
			kindType, ok := lo.Find(PODS_KIND, func(i string) bool { return i == value })
			if ok {
				manifestList[key] = SetLabelValue(res, PODS_LABEL[kindType], labelKey, helm.GetDependencyLabel(key))
			}
		}
	}
}

func GetNamespace(manifestList helm.HelmManifestList) string {
	result := lo.Values(manifestList)
	manifests_with_ns := lo.Filter(result, func(item helm.HelmManifest, idx int) bool {
		meta := item["metadata"].(helm.HelmManifest)
		if meta == nil {
			return false
		}
		namespace := meta["namespace"]
		return namespace != nil
	})

	namespaces := lo.Map(manifests_with_ns, func(item helm.HelmManifest, index int) string {
		meta := item["metadata"].(helm.HelmManifest)
		return meta["namespace"].(string)
	})
	log.WithField("All", "Namespaces").Infoln(lo.Uniq(namespaces))
	ns := findMostRepeatedItem(namespaces)
	log.WithField("MostUsed", "Namespace").Infoln(ns)

	return ns
}

func findMostRepeatedItem(arr []string) string {
	counter := make(map[string]int)

	for _, item := range arr {
		counter[item]++
	}

	maxCount := 0
	mostRepeatedItem := ""

	for item, count := range counter {
		if count > maxCount {
			maxCount = count
			mostRepeatedItem = item
		}
	}

	return mostRepeatedItem
}
