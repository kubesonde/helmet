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
package helm

import (
	"sort"
	"testing"

	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
	"gotest.tools/v3/assert"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHelmUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Helm suite")
}

var _ = Describe("GroupManifestsByDependency", func() {
	It("Creates only one entry if no dependencies are provided", func() {
		manifests := HelmManifestList{
			"mychart/templates/abc.yaml": {"foo": 2},
			"mychart/templates/svc.yaml": {"bar": 2},
		}

		groupedManifests := GroupManifestsByDependency(manifests)

		Expect(lo.Keys(groupedManifests)).To(Equal([]string{"mychart"}))
		Expect(groupedManifests["mychart"]).To(HaveLen(2))
	})
	It("Creates two entries if there is a single dependency", func() {
		manifests := HelmManifestList{
			"mychart/templates/abc.yaml":               {"foo": 2},
			"mychart/charts/mydep/templates/svc2.yaml": {"baz": 2},
			"mychart/charts/mydep/templates/svc.yaml":  {"bar": 2},
		}

		groupedManifests := GroupManifestsByDependency(manifests)

		keys := lo.Keys(groupedManifests)

		sort.Strings(keys)

		Expect(keys).To(Equal([]string{"mychart", "mychart_mydep"}))
		Expect(groupedManifests["mychart"]).To(HaveLen(1))
		Expect(groupedManifests["mychart_mydep"]).To(HaveLen(2))
	})
})

var _ = Describe("isFileName", func() {
	It("Recognizes a filename in a comment", func() {
		Expect(isFileName("Hello")).To(BeFalse())
		Expect(isFileName("# Source: Hello")).To(BeFalse())
		Expect(isFileName("# Sourced: Hello.yaml")).To(BeFalse())
		Expect(isFileName("# Source: hello.yaml")).To(BeTrue())
		Expect(isFileName("# Source: hello.yml")).To(BeTrue())
	})
})

var _ = Describe("computeFilenameForResource", func() {
	It("Computes filename when metadata and name are available", func() {
		manifest := `
kind: Pod
metadata:
  name: manifestName`

		var formattedManifest HelmManifest
		lo.Must0(yaml.Unmarshal([]byte(manifest), &formattedManifest))

		filename := computeFilenameForResource("my-release", formattedManifest)

		Expect(filename).To(Equal("manifestName-unknown.yaml"))
	})
	It("Computes filename when only metadata is available", func() {
		manifest := `
kind: Pod
metadata:
  foo: manifestName`

		var formattedManifest HelmManifest
		lo.Must0(yaml.Unmarshal([]byte(manifest), &formattedManifest))

		filename := computeFilenameForResource("my-release", formattedManifest)

		Expect(filename).To(Equal("my-release-unknown.yaml"))
	})
	It("Computes filename when metadata is not  available", func() {
		manifest := `
kind: Pod
nothing:
  foo: manifestName`

		var formattedManifest HelmManifest
		lo.Must0(yaml.Unmarshal([]byte(manifest), &formattedManifest))

		filename := computeFilenameForResource("my-release", formattedManifest)

		Expect(filename).To(Equal("my-release-unknown.yaml"))
	})
})

var _ = Describe("getResourcesWithName", func() {
	It("Finds resources", func() {
		releaseName := "testRelease"
		resources := []string{
			`# Source: folder1/example-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
	image: nginx:1.14.2
	ports:
	- containerPort: 80
`,
			`# Source: testRelease/example-pod2.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
	image: nginx:1.14.2
	ports:
	- containerPort: 80
`,
			`
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
	image: nginx:1.14.2
	ports:
	- containerPort: 80
`,
		}
		manifestList := getResourcesWithName(releaseName, resources)
		expectedKeys := []string{"folder1/example-pod.yaml", "testRelease/example-pod2.yaml", "nginx-unknown.yaml"}

		for k := range manifestList {
			Expect(lo.Contains(expectedKeys, k)).To(BeTrue())
		}
	})
})

var _ = Describe("validateMisconfigurationsInChart", func() {
	It("validatesConfigurations", func() {
		correctConfiguration := HelmManifestList{
			"file1.yaml": HelmManifest{"hostNetwork": false},
		}
		invalidConfiguration := HelmManifestList{
			"file1.yaml": HelmManifest{"hostNetwork": true},
		}
		Expect(ValidateMisconfigurationsInChart(correctConfiguration, true)).To(BeTrue())
		Expect(ValidateMisconfigurationsInChart(invalidConfiguration, true)).To(BeFalse())
	})
})

func Test_getNameSpaceFromService(t *testing.T) {
	exampleService := make(HelmManifest)
	nameSpace := make(map[string]interface{})
	nameSpace["namespace"] = "customNamespace"
	nameSpace["name"] = "custom"
	labels := make(map[string]interface{})
	labels["helm.sh/chart"] = "chart"
	nameSpace["labels"] = labels
	exampleService["metadata"] = nameSpace
	exampleService["apiVersion"] = "v1"
	exampleService["kind"] = "Service"

	assert.Equal(t, "customNamespace", GetNameSpaceFromService(exampleService))
}
