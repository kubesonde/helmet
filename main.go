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

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/samber/lo"
	"helmet.io/pkg/graph"
	"helmet.io/pkg/helm"
)

var output_dir = "output_dir"

// log                = logging.LOGGER.WithFields(logrus.Fields{
//	"source": "postrender",
// }).

func emptyFolder(folder string) {
	fldRead := lo.Must1(os.Open(filepath.Clean(folder)))
	files := lo.Must1(fldRead.Readdir(0))

	for i := range files {
		fileHere := files[i]

		nameHere := fileHere.Name()
		fullPath := fmt.Sprintf("%s/%s", folder, nameHere)

		lo.Must0(os.Remove(fullPath))
	}
}

func processChart(inputFile *string, verbose bool) {
	if verbose {
		fmt.Printf("Analyzing %s\n", *inputFile)
	}

	data := lo.Must1(os.ReadFile(*inputFile))
	manifestList := helm.GetManifestListFromString(string(data))
	graph.ProcessChart(manifestList)
}

func main() {
	emptyFolder(output_dir)

	inputFile := flag.String("input", "./input.txt", "Path to the input file")
	folder := flag.String("d", "", "Path to a directory with chart templates")
	flag.Parse()
	if *folder == "" {
		processChart(inputFile, true)
	} else {
		entries := lo.Must1(os.ReadDir(*folder))
		for _, e := range entries {
			path := fmt.Sprintf("%s%s", *folder, e.Name())

			processChart(&path, false)
		}
	}
}
