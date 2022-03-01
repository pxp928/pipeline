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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
)

func (sc *SpireControllerApiClient) fetchSVID() (*x509svid.SVID, error) {
	xsvid, err := sc.workloadAPI.FetchX509SVID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch controller SVID: %s", err)
	}
	return xsvid, nil
}

func (sc *SpireControllerApiClient) VerifyTaskRunResults(rs []v1beta1.TaskRunResult, tr *v1beta1.TaskRun) error {
	resultMap := map[string]v1beta1.TaskRunResult{}
	for _, r := range rs {
		resultMap[r.Name] = r
	}

	cert, err := getSVID(resultMap)
	if err != nil {
		return err
	}

	trust, err := getTrustBundle(sc.workloadAPI, context.Background())
	if err != nil {
		return err
	}

	if err := verifyManifest(resultMap); err != nil {
		return err
	}

	if err := verifyCertURI(cert, tr, sc.config.TrustDomain); err != nil {
		return err
	}

	if err := verifyCertificateTrust(cert, trust); err != nil {
		return err
	}

	for key, _ := range resultMap {
		if strings.HasSuffix(key, ".sig") {
			continue
		}
		if key == "SVID" {
			continue
		}
		if err := verifyOne(cert.PublicKey, key, resultMap); err != nil {
			return err
		}
	}

	return nil
}

func (sc *SpireControllerApiClient) AppendStatusAnnotation(tr *v1beta1.TaskRun) error {
	// Add status hash
	current, err := hashTaskrunStatus(tr)
	if err != nil {
		return err
	}
	tr.Annotations[TaskRunStatusHashAnnotation] = current

	// Sign with controller private key
	xsvid, err := sc.fetchSVID()
	if err != nil {
		return err
	}

	s, err := signWithKey(xsvid, current)
	if err != nil {
		return err
	}
	tr.Annotations[taskRunStatusHashSigAnnotation] = base64.StdEncoding.EncodeToString(s)

	// Store Controller SVID
	p := pem.EncodeToMemory(&pem.Block{
		Bytes: xsvid.Certificates[0].Raw,
		Type:  "CERTIFICATE",
	})
	tr.Annotations[controllerSvidAnnotation] = string(p)
	return nil

}

func hashTaskrunStatus(tr *v1beta1.TaskRun) (string, error) {
	s, err := json.Marshal(tr.Status)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(s)), nil
}

func CheckStatusAnnotationHash(tr *v1beta1.TaskRun) error {
	// get stored hash of status
	hash := tr.Annotations[TaskRunStatusHashAnnotation]
	// get current hash of status
	current, err := hashTaskrunStatus(tr)
	if err != nil {
		return err
	}
	if hash != current {
		return fmt.Errorf("current status hash and stored annotation hash does not match! Annotation Hash: %s, Current Status Hash: %s", hash, current)
	}
	return nil
}

func getSVID(resultMap map[string]v1beta1.TaskRunResult) (*x509.Certificate, error) {
	svid, ok := resultMap["SVID"]
	if !ok {
		return nil, errors.New("no SVID found")
	}
	block, _ := pem.Decode([]byte(svid.Value))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid SVID: %s", err)
	}
	return cert, nil
}

func getTrustBundle(client *workloadapi.Client, ctx context.Context) (*x509.CertPool, error) {
	x509set, err := client.FetchX509Bundles(ctx)
	if err != nil {
		return nil, err
	}
	x509Bundle := x509set.Bundles()
	if err != nil {
		return nil, err
	}
	trustPool := x509.NewCertPool()
	for _, c := range x509Bundle[0].X509Authorities() {
		trustPool.AddCert(c)
	}
	return trustPool, nil
}

func getFullPath(tr *v1beta1.TaskRun) string {
	// URI:spiffe://example.org/ns/default/taskrun/cache-image-pipelinerun-r4r22-fetch-from-git
	return fmt.Sprintf("/ns/%s/taskrun/%s", tr.Namespace, tr.Name)
}

func verifyCertURI(cert *x509.Certificate, tr *v1beta1.TaskRun, trustDomain string) error {
	path := getFullPath(tr)
	if len(cert.URIs) > 0 {
		if cert.URIs[0].Host != trustDomain {
			return fmt.Errorf("cert uri: %s does not match trust domain: %s", cert.URIs[0].Host, trustDomain)
		}
		if cert.URIs[0].Path != path {
			return fmt.Errorf("cert uri: %s does not match taskrun: %s", cert.URIs[0].Path, path)
		}
	} else {
		return fmt.Errorf("cert uri missing for taskrun: %s", tr.Name)
	}

	return nil
}

func verifyCertificateTrust(cert *x509.Certificate, rootCertPool *x509.CertPool) error {
	verifyOptions := x509.VerifyOptions{
		Roots: rootCertPool,
	}
	chains, err := cert.Verify(verifyOptions)
	if len(chains) == 0 || err != nil {
		return fmt.Errorf("cert cannot be verified by provided roots")
	}
	return nil
}

func verifyManifest(results map[string]v1beta1.TaskRunResult) error {
	manifest, ok := results["RESULT_MANIFEST"]
	if !ok {
		return errors.New("no manifest found in results")
	}
	s := strings.Split(manifest.Value, ",")
	for _, key := range s {
		_, found := results[key]
		if !found {
			return fmt.Errorf("no result found for %s but is part of the manifest %s", key, manifest.Value)
		}
	}
	return nil
}

func verifyOne(pub interface{}, key string, results map[string]v1beta1.TaskRunResult) error {
	signature, ok := results[key+".sig"]
	if !ok {
		return fmt.Errorf("no signature found for %s", key)
	}
	b, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil {
		return fmt.Errorf("invalid signature: %s", err)
	}
	h := sha256.Sum256([]byte(results[key].Value))
	// Check val against sig
	switch t := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(t, h[:], b) {
			return errors.New("invalid signature")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(t, crypto.SHA256, h[:], b)
	case ed25519.PublicKey:
		if !ed25519.Verify(t, []byte(results[key].Value), b) {
			return errors.New("invalid signature")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type: %s", t)
	}
}
