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
	"time"

	"github.com/pkg/errors"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	spireconfig "github.com/tektoncd/pipeline/pkg/spire/config"
)

type SpireEntrypointerApiClient struct {
	config spireconfig.SpireConfig
	client *workloadapi.Client
}

func (w *SpireEntrypointerApiClient) DialClient(ctx context.Context) (*workloadapi.Client, error) {
	if w.client != nil {
		return w.client, nil
	}
	return w.dial(ctx)
}

func (w *SpireEntrypointerApiClient) dial(ctx context.Context) (*workloadapi.Client, error) {
	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+w.config.SocketPath))
	if err != nil {
		return nil, errors.Errorf("Spire workload API not initalized due to error: %w", err.Error())
	}
	w.client = client
	return client, nil
}

func (w *SpireEntrypointerApiClient) getxsvid() *x509svid.SVID {
	backoffSeconds := 2
	var xsvid *x509svid.SVID = nil
	var err error = nil
	for i := 0; i < 20; i += backoffSeconds {
		xsvid, err = w.client.FetchX509SVID(context.Background())
		if err == nil {
			break
		}
		time.Sleep(time.Duration(backoffSeconds) * time.Second)
	}
	return xsvid
}

func NewSpireEntrypointerApiClient(c spireconfig.SpireConfig) *SpireEntrypointerApiClient {
	return &SpireEntrypointerApiClient{
		config: c,
	}
}

func (w *SpireEntrypointerApiClient) Close() {
	err := w.client.Close()
	if err != nil {
		// Log error
	}
}
