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
	"time"

	"github.com/pkg/errors"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spiffetypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	corev1 "k8s.io/api/core/v1"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	spireconfig "github.com/tektoncd/pipeline/pkg/spire/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

const (
	TaskRunStatusHashAnnotation    = "tekton.dev/status-hash"
	taskRunStatusHashSigAnnotation = "tekton.dev/status-hash-sig"
	controllerSvidAnnotation       = "tekton.dev/controller-svid"
)

type SpireServerApiClient struct {
	config       spireconfig.SpireConfig
	serverConn   *grpc.ClientConn
	workloadConn *workloadapi.X509Source
	entryClient  entryv1.EntryClient
	workloadAPI  *workloadapi.Client
	SVID         *x509svid.SVID
	ctx          context.Context
}

func (sc *SpireServerApiClient) checkClient(ctx context.Context) error {
	if sc.entryClient == nil || sc.workloadConn == nil || sc.serverConn == nil {
		return sc.dial(ctx)
	}
	return nil
}

func (sc *SpireServerApiClient) dial(ctx context.Context) error {
	sc.ctx = ctx
	if sc.workloadConn == nil {
		// Create X509Source
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+sc.config.SocketPath)))
		if err != nil {
			return fmt.Errorf("unable to create X509Source for SPIFFE client: %w", err)
		}
		sc.workloadConn = source
	}

	if sc.workloadAPI == nil {
		client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+sc.config.SocketPath))
		if err != nil {
			return fmt.Errorf("spire workload API not initalized due to error: %s", err)
		}
		sc.workloadAPI = client
	}

	if sc.serverConn == nil {
		// Create connection
		tlsConfig := tlsconfig.MTLSClientConfig(sc.workloadConn, sc.workloadConn, tlsconfig.AuthorizeAny())
		conn, err := grpc.DialContext(ctx, sc.config.ServerAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		if err != nil {
			sc.workloadConn.Close()
			sc.workloadConn = nil
			return fmt.Errorf("unable to dial SPIRE server: %w", err)
		}
		sc.serverConn = conn
	}

	sc.entryClient = entryv1.NewEntryClient(sc.serverConn)

	return nil
}

func NewSpireServerApiClient(c spireconfig.SpireConfig) *SpireServerApiClient {
	return &SpireServerApiClient{
		config: c,
	}
}

func (sc *SpireServerApiClient) NodeEntry(nodeName string) *spiffetypes.Entry {
	selectors := []*spiffetypes.Selector{
		{
			Type:  "k8s_psat",
			Value: "agent_ns:spire",
		},
		{
			Type:  "k8s_psat",
			Value: "agent_node_name:" + nodeName,
		},
	}

	return &spiffetypes.Entry{
		SpiffeId: &spiffetypes.SPIFFEID{
			TrustDomain: sc.config.TrustDomain,
			Path:        fmt.Sprintf("%v%v", sc.config.NodeAliasPrefix, nodeName),
		},
		ParentId: &spiffetypes.SPIFFEID{
			TrustDomain: sc.config.TrustDomain,
			Path:        "/spire/server",
		},
		Selectors: selectors,
	}
}

func (sc *SpireServerApiClient) WorkloadEntry(tr *v1beta1.TaskRun, pod *corev1.Pod, expiry int64) *spiffetypes.Entry {
	// Note: We can potentially add attestation on the container images as well since
	// the information is available here.
	selectors := []*spiffetypes.Selector{
		{
			Type:  "k8s",
			Value: "pod-uid:" + string(pod.UID),
		},
		{
			Type:  "k8s",
			Value: "pod-name:" + pod.Name,
		},
	}

	return &spiffetypes.Entry{
		SpiffeId: &spiffetypes.SPIFFEID{
			TrustDomain: sc.config.TrustDomain,
			Path:        fmt.Sprintf("/ns/%v/taskrun/%v", tr.Namespace, tr.Name),
		},
		ParentId: &spiffetypes.SPIFFEID{
			TrustDomain: sc.config.TrustDomain,
			Path:        fmt.Sprintf("%v%v", sc.config.NodeAliasPrefix, pod.Spec.NodeName),
		},
		Selectors: selectors,
		ExpiresAt: expiry,
	}
}

// ttl is the TTL for the SPIRE entry in seconds, not the SVID TTL
func (sc *SpireServerApiClient) CreateEntries(ctx context.Context, tr *v1beta1.TaskRun, pod *corev1.Pod, ttl int) error {
	err := sc.checkClient(ctx)
	if err != nil {
		return err
	}

	expiryTime := time.Now().Unix() + int64(ttl)
	entries := []*spiffetypes.Entry{
		sc.NodeEntry(pod.Spec.NodeName),
		sc.WorkloadEntry(tr, pod, expiryTime),
	}

	req := entryv1.BatchCreateEntryRequest{
		Entries: entries,
	}

	resp, err := sc.entryClient.BatchCreateEntry(ctx, &req)
	if err != nil {
		return err
	}

	if len(resp.Results) != len(entries) {
		return fmt.Errorf("batch create entry failed, malformed response expected %v result", len(entries))
	}

	var errPaths []string
	var errCodes []int32

	for _, r := range resp.Results {
		if codes.Code(r.Status.Code) != codes.AlreadyExists &&
			codes.Code(r.Status.Code) != codes.OK {
			errPaths = append(errPaths, r.Entry.SpiffeId.Path)
			errCodes = append(errCodes, r.Status.Code)
		}
	}

	if len(errPaths) != 0 {
		return fmt.Errorf("batch create entry failed for entries %+v with codes %+v", errPaths, errCodes)
	}
	return nil
}

func (sc *SpireServerApiClient) getEntries(ctx context.Context, tr *v1beta1.TaskRun, pod *corev1.Pod) ([]*spiffetypes.Entry, error) {
	req := &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{
			BySpiffeId: &spiffetypes.SPIFFEID{
				TrustDomain: sc.config.TrustDomain,
				Path:        fmt.Sprintf("/ns/%v/taskrun/%v", tr.Namespace, tr.Name),
			},
		},
	}

	entries := []*spiffetypes.Entry{}
	for {
		resp, err := sc.entryClient.ListEntries(ctx, req)
		if err != nil {
			return nil, err
		}

		entries = append(entries, resp.Entries...)

		if resp.NextPageToken == "" {
			break
		}

		req.PageToken = resp.NextPageToken
	}

	return entries, nil
}

func (sc *SpireServerApiClient) DeleteEntry(ctx context.Context, tr *v1beta1.TaskRun, pod *corev1.Pod) error {
	entries, err := sc.getEntries(ctx, tr, pod)
	if err != nil {
		return err
	}

	var ids []string
	for _, e := range entries {
		ids = append(ids, e.Id)
	}

	req := &entryv1.BatchDeleteEntryRequest{
		Ids: ids,
	}
	resp, err := sc.entryClient.BatchDeleteEntry(ctx, req)
	if err != nil {
		return err
	}

	var errIds []string
	var errCodes []int32

	for _, r := range resp.Results {
		if codes.Code(r.Status.Code) != codes.NotFound &&
			codes.Code(r.Status.Code) != codes.OK {
			errIds = append(errIds, r.Id)
			errCodes = append(errCodes, r.Status.Code)
		}
	}

	if len(errIds) != 0 {
		return fmt.Errorf("batch delete entry failed for ids %+v with codes %+v", errIds, errCodes)
	}

	return nil
}

func (sc *SpireServerApiClient) Close() {
	err := sc.serverConn.Close()
	if err != nil {
		// Log error
	}
	err = sc.workloadConn.Close()
	if err != nil {
		// Log error
	}
}

func (sc *SpireServerApiClient) fetchSVID() (*x509svid.SVID, error) {
	if sc.SVID != nil {
		return sc.SVID, nil
	}
	xsvid, err := sc.workloadAPI.FetchX509SVID(sc.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch controller SVID: %s", err)
	}
	sc.SVID = xsvid
	return sc.SVID, nil
}

func (sc *SpireServerApiClient) CheckValidated(rs []v1beta1.TaskRunResult, tr *v1beta1.TaskRun) error {
	resultMap := map[string]v1beta1.TaskRunResult{}
	for _, r := range rs {
		resultMap[r.Name] = r
	}

	cert, err := getSVID(resultMap)
	if err != nil {
		return err
	}

	trust, err := getTrustBundle(sc.workloadAPI, sc.ctx)
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

func (sc *SpireServerApiClient) AppendStatusAnnotation(tr *v1beta1.TaskRun) error {
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

func verifyCertURI(cert *x509.Certificate, tr *v1beta1.TaskRun, trustDomain string) error {
	// URI:spiffe://example.org/ns/default/taskrun/cache-image-pipelinerun-r4r22-fetch-from-git
	path := "/ns/" + tr.Namespace + "/taskrun/" + tr.Name
	if cert.URIs[0].Host != trustDomain {
		return fmt.Errorf("cert uri: %s does not match trust domain: %s", cert.URIs[0].Host, trustDomain)
	}
	if cert.URIs[0].Path != path {
		return fmt.Errorf("cert uri: %s does not match taskrun: %s", cert.URIs[0].Path, path)
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
