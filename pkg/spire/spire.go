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
