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
	"fmt"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	spiffetypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	corev1 "k8s.io/api/core/v1"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	spireconfig "github.com/tektoncd/pipeline/pkg/spire/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

type SpireServerApiClient struct {
	config       spireconfig.SpireConfig
	serverConn   *grpc.ClientConn
	workloadConn *workloadapi.X509Source
	entryClient  entryv1.EntryClient
}

func (sc *SpireServerApiClient) checkClient(ctx context.Context) error {
	if sc.entryClient == nil || sc.workloadConn == nil || sc.serverConn == nil {
		return sc.dial(ctx)
	}
	return nil
}

func (sc *SpireServerApiClient) dial(ctx context.Context) error {
	if sc.workloadConn == nil {
		// Create X509Source
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+sc.config.SocketPath)))
		if err != nil {
			return fmt.Errorf("Unable to create X509Source for SPIFFE client: %w", err)
		}
		sc.workloadConn = source
	}

	if sc.serverConn == nil {
		// Create connection
		tlsConfig := tlsconfig.MTLSClientConfig(sc.workloadConn, sc.workloadConn, tlsconfig.AuthorizeAny())
		conn, err := grpc.DialContext(ctx, sc.config.ServerAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		if err != nil {
			sc.workloadConn.Close()
			sc.workloadConn = nil
			return fmt.Errorf("Unable to dial SPIRE server: %w", err)
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

func (sc *SpireServerApiClient) WorkloadEntry(tr *v1beta1.TaskRun, pod *corev1.Pod) *spiffetypes.Entry {
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
	}
}

func (sc *SpireServerApiClient) CreateEntries(ctx context.Context, tr *v1beta1.TaskRun, pod *corev1.Pod) error {
	err := sc.checkClient(ctx)
	if err != nil {
		return err
	}
	entries := []*spiffetypes.Entry{
		sc.NodeEntry(pod.Spec.NodeName),
		sc.WorkloadEntry(tr, pod),
	}

	req := entryv1.BatchCreateEntryRequest{
		Entries: entries,
	}

	resp, err := sc.entryClient.BatchCreateEntry(ctx, &req)
	if err != nil {
		return err
	}

	if len(resp.Results) != len(entries) {
		return fmt.Errorf("Batch create entry failed, malformed response expected %v result", len(entries))
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
		return fmt.Errorf("Batch create entry failed for entries %+v with codes %+v", errPaths, errCodes)
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
