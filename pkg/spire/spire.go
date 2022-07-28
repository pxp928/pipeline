/*
Copyright 2022 The Tekton Authors

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

// The spire package is used to interact with the Spire server and Spire agent respectively.
// The pipeline controller (once registered) is able to create and delete entries in the Spire server
// for the various TaskRuns that it instantiates. The TaskRun is able to attest to the Spire agent
// and obtains the valid SVID (SPIFFE Verifiable Identity Document) to sign the TaskRun results.
// Separately, the pipeline controller SVID is used to sign the TaskRun Status to validate no modification
// during the TaskRun execution. Each TaskRun result and status is verified and validated once the
// TaskRun execution is completed. Tekton Chains will also validate the results and status before
// signing and creating attestation for the TaskRun.
package spire

import (
	"context"

	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

const (
	// KeySVID key used by TaskRun SVID
	KeySVID = "SVID"
	// KeySignatureSuffix is the suffix of the keys that contain signatures
	KeySignatureSuffix = ".sig"
	// KeyResultManifest key used to get the result manifest from the results
	KeyResultManifest = "RESULT_MANIFEST"
	// WorkloadAPI is the name of the SPIFFE/SPIRE CSI Driver volume
	WorkloadAPI = "spiffe-workload-api"
	// VolumeMountPath is the volume mount in the the pods to access the SPIFFE/SPIRE agent workload API
	VolumeMountPath = "/spiffe-workload-api"
)

// ControllerAPIClient interface maps to the spire controller API to interact with spire
type ControllerAPIClient interface {
	Close() error
	CreateEntries(ctx context.Context, tr *v1beta1.TaskRun, pod *corev1.Pod, ttl int) error
	DeleteEntry(ctx context.Context, tr *v1beta1.TaskRun, pod *corev1.Pod) error
	VerifyTaskRunResults(ctx context.Context, prs []v1beta1.PipelineResourceResult, tr *v1beta1.TaskRun) error
}

// EntrypointerAPIClient interface maps to the spire entrypointer API to interact with spire
type EntrypointerAPIClient interface {
	Close() error
	// Sign returns the signature material to be put in the PipelineResourceResult to append to the output results
	Sign(ctx context.Context, results []v1beta1.PipelineResourceResult) ([]v1beta1.PipelineResourceResult, error)
}
