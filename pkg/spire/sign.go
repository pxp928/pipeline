/*
Copyright 2019 The Tekton Authors

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

package spire

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"strings"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
)

func (w *SpireEntrypointerApiClient) Sign(results []v1beta1.PipelineResourceResult) ([]v1beta1.PipelineResourceResult, error) {
	xsvid := w.getxsvid()

	output := []v1beta1.PipelineResourceResult{}
	if len(results) > 1 {
		p := pem.EncodeToMemory(&pem.Block{
			Bytes: xsvid.Certificates[0].Raw,
			Type:  "CERTIFICATE",
		})
		output = append(output, v1beta1.PipelineResourceResult{
			Key:        "SVID",
			Value:      string(p),
			ResultType: v1beta1.TaskRunResultType,
		})
	}
	for _, r := range results {
		s, err := signWithKey(xsvid, r.Value)
		if err != nil {
			return nil, err
		}
		output = append(output, v1beta1.PipelineResourceResult{
			Key:        r.Key + ".sig",
			Value:      base64.StdEncoding.EncodeToString(s),
			ResultType: v1beta1.TaskRunResultType,
		})
	}
	// get complete manifest of keys such that it can be verified
	manifest := getManifest(results)
	if manifest != "" {
		output = append(output, v1beta1.PipelineResourceResult{
			Key:        "RESULT_MANIFEST",
			Value:      manifest,
			ResultType: v1beta1.TaskRunResultType,
		})
		manifestSig, err := signWithKey(xsvid, manifest)
		if err != nil {
			return nil, err
		}
		output = append(output, v1beta1.PipelineResourceResult{
			Key:        "RESULT_MANIFEST.sig",
			Value:      base64.StdEncoding.EncodeToString(manifestSig),
			ResultType: v1beta1.TaskRunResultType,
		})
	}

	return output, nil
}

func signWithKey(xsvid *x509svid.SVID, value string) ([]byte, error) {
	dgst := sha256.Sum256([]byte(value))
	s, err := xsvid.PrivateKey.Sign(rand.Reader, dgst[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func getManifest(results []v1beta1.PipelineResourceResult) string {
	keys := []string{}
	for _, r := range results {
		if strings.HasSuffix(r.Key, ".sig") {
			continue
		}
		if r.Key == "SVID" {
			continue
		}
		keys = append(keys, r.Key)
	}
	return strings.Join(keys, ",")
}
