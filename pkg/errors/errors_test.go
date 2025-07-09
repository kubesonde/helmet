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
	"testing"

	"github.com/samber/lo"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestErrors(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Error suite")
}

var _ = Describe("String to error", func() {
	It("Returns default message for unknown error", func() {
		Expect(StringToError("does not exist")).To(Equal(Unknown))
	})
	It("Recognizes correct messages", func() {
		errorStrings := []string{
			"chart requires kubeVersion",
			"unable to build kubernetes objects",
			"ensure CRDs are installed first",
			"A value for one of the following variables is required",
			"execution error at",
			"no such host",
			"cluster unreachable",
		}
		expectedErrors := []HelmError{
			IncorrectK8sVersion,
			ValidationError,
			MissingCRDs,
			MissingVariable,
			InvalidVariable,
			NoInternet,
			ClusterUnreachable,
		}
		lo.ForEach(errorStrings, func(err string, index int) {
			Expect(StringToError(err)).To(Equal(expectedErrors[index]))
		})
	})
})
