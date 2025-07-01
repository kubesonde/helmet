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

package errors

import (
	"strings"
)

type HelmError string

const (
	TemplateToYamlError HelmError = "TEMPLATE_TO_YAML_ERROR"
	IncorrectK8sVersion HelmError = "WRONG_K8S_VERSION"
	ValidationError     HelmError = "VALIDATION_ERROR"
	MissingCRDs         HelmError = "MISSING_CRD"
	MissingVariable     HelmError = "MISSING_VARIABLE"
	Unknown             HelmError = "UNKNOWN"
	InvalidVariable     HelmError = "INVALID_VARIABLE"
	NoInternet          HelmError = "NO_INTERNET"
	ClusterUnreachable  HelmError = "CLUSTER_UNREACHABLE"
	ServiceIssue        HelmError = "SERVICE_ISSUE"
	MissingTargetPort   HelmError = "MISSING_TARGET_PORT"
)

func StringToError(errorstring string) HelmError {
	kubev := "chart requires kubeVersion"
	build := "unable to build kubernetes objects"
	crds := "ensure CRDs are installed first"
	missingvar := "A value for one of the following variables is required"
	mandatory_missed := "execution error at"
	no_internet := "no such host"
	unreachable := "cluster unreachable"
	if strings.Contains(errorstring, kubev) {
		return IncorrectK8sVersion
	} else if strings.Contains(errorstring, crds) {
		return MissingCRDs
	} else if strings.Contains(errorstring, missingvar) {
		return MissingVariable
	} else if strings.Contains(errorstring, build) {
		return ValidationError
	} else if strings.Contains(errorstring, mandatory_missed) {
		return InvalidVariable
	} else if strings.Contains(errorstring, no_internet) {
		return NoInternet
	} else if strings.Contains(errorstring, unreachable) {
		return ClusterUnreachable
	}
	return Unknown
}
