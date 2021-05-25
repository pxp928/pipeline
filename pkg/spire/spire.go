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

type SpiffeServerApiClient struct {
	serverConn   *grpc.ClientConn
	workloadConn *workloadapi.X509Source
	entryClient  entryv1.EntryClient
	config       spireconfig.SpireConfig
}

func NewSpiffeServerApiClient(ctx context.Context, c spireconfig.SpireConfig) (*SpiffeServerApiClient, error) {
	// Create X509Source
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+c.SocketPath)))
	if err != nil {
		return nil, fmt.Errorf("Unable to create X509Source for SPIFFE client: %w", err)
	}

	// Create connection
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	conn, err := grpc.DialContext(ctx, c.ServerAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("Unable to dial SPIRE server: %w", err)
	}

	return &SpiffeServerApiClient{
		serverConn:   conn,
		workloadConn: source,
		entryClient:  entryv1.NewEntryClient(conn),
		config:       c,
	}, nil
}

func (sc *SpiffeServerApiClient) CreateNodeEntry(ctx context.Context, nodeName string) error {
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

	entries := []*spiffetypes.Entry{
		{
			SpiffeId: &spiffetypes.SPIFFEID{
				TrustDomain: sc.config.TrustDomain,
				Path:        fmt.Sprintf("%v%v", sc.config.NodeAliasPrefix, nodeName),
			},
			ParentId: &spiffetypes.SPIFFEID{
				TrustDomain: sc.config.TrustDomain,
				Path:        "/spire/server",
			},
			Selectors: selectors,
		},
	}

	req := entryv1.BatchCreateEntryRequest{
		Entries: entries,
	}

	resp, err := sc.entryClient.BatchCreateEntry(ctx, &req)
	if err != nil {
		return err
	}

	if len(resp.Results) != 1 {
		return fmt.Errorf("Batch create entry failed, malformed response expected 1 result")
	}

	res := resp.Results[0]
	if codes.Code(res.Status.Code) == codes.AlreadyExists ||
		codes.Code(res.Status.Code) == codes.OK {
		return nil
	}

	return fmt.Errorf("Batch create entry failed, code: %v", res.Status.Code)
}

func (sc *SpiffeServerApiClient) CreateWorkloadEntry(ctx context.Context, tr *v1beta1.TaskRun, pod *corev1.Pod) error {
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

	entries := []*spiffetypes.Entry{
		{
			SpiffeId: &spiffetypes.SPIFFEID{
				TrustDomain: sc.config.TrustDomain,
				Path:        fmt.Sprintf("/ns/%v/taskrun/%v", tr.Namespace, tr.Name),
			},
			ParentId: &spiffetypes.SPIFFEID{
				TrustDomain: sc.config.TrustDomain,
				Path:        fmt.Sprintf("%v%v", sc.config.NodeAliasPrefix, pod.Spec.NodeName),
			},
			Selectors: selectors,
		},
	}

	req := entryv1.BatchCreateEntryRequest{
		Entries: entries,
	}

	resp, err := sc.entryClient.BatchCreateEntry(ctx, &req)
	if err != nil {
		return err
	}

	if len(resp.Results) != 1 {
		return fmt.Errorf("Batch create entry failed, malformed response expected 1 result")
	}

	res := resp.Results[0]
	if codes.Code(res.Status.Code) == codes.AlreadyExists ||
		codes.Code(res.Status.Code) == codes.OK {
		return nil
	}

	return fmt.Errorf("Batch create entry failed, code: %v", res.Status.Code)
}

func (sc *SpiffeServerApiClient) Close() {
	err := sc.serverConn.Close()
	if err != nil {
		// Log error
	}
	err = sc.workloadConn.Close()
	if err != nil {
		// Log error
	}
}
