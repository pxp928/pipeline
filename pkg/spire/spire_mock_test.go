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
	"testing"
	"time"

	"github.com/tektoncd/pipeline/pkg/apis/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/apis"
	duckv1beta1 "knative.dev/pkg/apis/duck/v1beta1"
)

/*
type SpireControllerApiClient interface {
    AppendStatusInternalAnnotation(ctx context.Context, tr *v1beta1.TaskRun) error
    CheckSpireVerifiedFlag(tr *v1beta1.TaskRun) bool
    Close()
    CreateEntries(ctx context.Context, tr *v1beta1.TaskRun, pod *corev1.Pod, ttl int) error
    DeleteEntry(ctx context.Context, tr *v1beta1.TaskRun, pod *corev1.Pod) error
    VerifyStatusInternalAnnotation(ctx context.Context, tr *v1beta1.TaskRun, logger *zap.SugaredLogger) error
    VerifyTaskRunResults(ctx context.Context, prs []v1beta1.PipelineResourceResult, tr *v1beta1.TaskRun) error
}

type SpireEntrypointerApiClient interface {
	Close()
	Sign(ctx context.Context, results []v1beta1.PipelineResourceResult) ([]v1beta1.PipelineResourceResult, error)
}
*/

/*
   taskrun := &v1beta1.TaskRun{
       ObjectMeta: baseObjectMeta("test-pipeline-run-success-unit-test-1", "foo"),
       Spec: v1beta1.TaskRunSpec{
           TaskRef:            &v1beta1.TaskRef{Name: "unit-test-task"},
           ServiceAccountName: "test-sa",
           Resources:          &v1beta1.TaskRunResources{},
           Timeout:            &metav1.Duration{Duration: config.DefaultTimeoutMinutes * time.Minute},
       },
       Status: v1beta1.TaskRunStatus{
           Status: duckv1beta1.Status{
               Conditions: duckv1beta1.Conditions{
                   apis.Condition{
                       Type: apis.ConditionSucceeded,
                   },
               },
           },
           TaskRunStatusFields: v1beta1.TaskRunStatusFields{
               Steps: []v1beta1.StepState{{
                   ContainerState: corev1.ContainerState{
                       Terminated: &corev1.ContainerStateTerminated{ExitCode: int32(0)},
                   },
               }},
           },
       },
   }
*/
/*
spireMockClient := &SpireMockClient{}
	var (
		cc SpireControllerApiClient   = spireMockClient
		ec SpireEntrypointerApiClient = spireMockClient
	)


	trTests := []struct {
		tr *v1beta1.TaskRun
	}{
		{
			tr: testTaskRuns[0],
		},
		{
			tr: testTaskRuns[1],
		},
	}


*/

// Simple task run sign/verify
func TestSpireMock_TaskRunSign(t *testing.T) {
	spireMockClient := &SpireMockClient{}
	var (
		cc SpireControllerApiClient = spireMockClient
	)

	ctx := context.Background()
	var err error

	for _, tr := range testTaskRuns() {
		err = cc.AppendStatusInternalAnnotation(ctx, tr)
		if err != nil {
			t.Fatalf("failed to sign TaskRun: %v", err)
		}

		err = cc.VerifyStatusInternalAnnotation(ctx, tr, nil)
		if err != nil {
			t.Fatalf("failed to verify TaskRun: %v", err)
		}
	}
}

// test CheckSpireVerifiedFlag(tr *v1beta1.TaskRun) bool
func TestSpireMock_CheckSpireVerifiedFlag(t *testing.T) {

	spireMockClient := &SpireMockClient{}
	var (
		cc SpireControllerApiClient = spireMockClient
	)

	trs := testTaskRuns()
	tr := trs[0]

	if !cc.CheckSpireVerifiedFlag(tr) {
		t.Fatalf("verified flag should be unset")
	}

	if tr.Status.Status.Annotations == nil {
		tr.Status.Status.Annotations = map[string]string{}
	}
	tr.Status.Status.Annotations[NotVerifiedAnnotation] = "yes"

	if cc.CheckSpireVerifiedFlag(tr) {
		t.Fatalf("verified flag should be unset")
	}
}

// Task run check signed status is not the same with two taskruns
func TestSpireMock_CheckHashSimilarities(t *testing.T) {
	spireMockClient := &SpireMockClient{}
	var (
		cc SpireControllerApiClient = spireMockClient
	)

	ctx := context.Background()
	trs := testTaskRuns()
	tr1, tr2 := trs[0], trs[1]

	trs = testTaskRuns()
	tr1c, tr2c := trs[0], trs[1]

	tr2c.Status.Status.Annotations = map[string]string{"new": "value"}

	signTrs := []*v1beta1.TaskRun{tr1, tr1c, tr2, tr2c}

	for _, tr := range signTrs {
		err := cc.AppendStatusInternalAnnotation(ctx, tr)
		if err != nil {
			t.Fatalf("failed to sign TaskRun: %v", err)
		}
	}

	if getHash(tr1) != getHash(tr1c) {
		t.Fatalf("2 hashes of the same status should be same")
	}

	if getHash(tr1) == getHash(tr2) {
		t.Fatalf("2 hashes of different status should not be the same")
	}

	if getHash(tr2) != getHash(tr2c) {
		t.Fatalf("2 hashes of the same status should be same (ignoring Status.Status)")
	}
}

// Task run sign, modify signature/hash/svid/content and verify
func TestSpireMock_CheckTamper(t *testing.T) {

	tests := []struct {
		// description of test case
		desc string
		// annotations to set
		setAnnotations map[string]string
		// modify the status
		modifyStatus bool
		// modify the hash to match the new status but not the signature
		modifyHashToMatch bool
		// if test should pass
		verify bool
	}{
		{
			desc:   "tamper nothing",
			verify: true,
		},
		{
			desc: "tamper unrelated hash",
			setAnnotations: map[string]string{
				"unrelated-hash": "change",
			},
			verify: true,
		},
		{
			desc: "tamper status hash",
			setAnnotations: map[string]string{
				TaskRunStatusHashAnnotation: "change-hash",
			},
			verify: false,
		},
		{
			desc: "tamper sig",
			setAnnotations: map[string]string{
				taskRunStatusHashSigAnnotation: "change-sig",
			},
			verify: false,
		},
		{
			desc: "tamper SVID",
			setAnnotations: map[string]string{
				controllerSvidAnnotation: "change-svid",
			},
			verify: false,
		},
		{
			desc: "delete status hash",
			setAnnotations: map[string]string{
				TaskRunStatusHashAnnotation: "",
			},
			verify: false,
		},
		{
			desc: "delete sig",
			setAnnotations: map[string]string{
				taskRunStatusHashSigAnnotation: "",
			},
			verify: false,
		},
		{
			desc: "delete SVID",
			setAnnotations: map[string]string{
				controllerSvidAnnotation: "",
			},
			verify: false,
		},
		{
			desc:         "tamper status",
			modifyStatus: true,
			verify:       false,
		},
		{
			desc:              "tamper status and status hash",
			modifyStatus:      true,
			modifyHashToMatch: true,
			verify:            false,
		},
	}
	for _, tt := range tests {
		spireMockClient := &SpireMockClient{}
		var (
			cc SpireControllerApiClient = spireMockClient
		)

		ctx := context.Background()
		for _, tr := range testTaskRuns() {
			err := cc.AppendStatusInternalAnnotation(ctx, tr)
			if err != nil {
				t.Fatalf("failed to sign TaskRun: %v", err)
			}

			if tr.Status.Status.Annotations == nil {
				tr.Status.Status.Annotations = map[string]string{}
			}

			if tt.setAnnotations != nil {
				for k, v := range tt.setAnnotations {
					tr.Status.Status.Annotations[k] = v
				}
			}

			if tt.modifyStatus {
				tr.Status.TaskRunStatusFields.Steps = append(tr.Status.TaskRunStatusFields.Steps, v1beta1.StepState{
					ContainerState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{ExitCode: int32(54321)},
					}})
			}

			if tt.modifyHashToMatch {
				h, _ := hashTaskrunStatusInternal(tr)
				tr.Status.Status.Annotations[TaskRunStatusHashAnnotation] = h
			}

			verified := cc.VerifyStatusInternalAnnotation(ctx, tr, nil) == nil
			if verified != tt.verify {
				t.Fatalf("test %v expected verify %v, got %v", tt.desc, tt.verify, verified)
			}
		}

	}

}

// Task result sign and verify
// Task result sign and verify fail without entry create

// Task result sign, modify signature/content and verify
func TestSpireMock_TaskRunResultsSign(t *testing.T) {}

func objectMeta(name, ns string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:        name,
		Namespace:   ns,
		Labels:      map[string]string{},
		Annotations: map[string]string{},
	}
}

func testTaskRuns() []*v1beta1.TaskRun {
	return []*v1beta1.TaskRun{
		// taskRun 1
		{
			ObjectMeta: objectMeta("taskrun-example", "foo"),
			Spec: v1beta1.TaskRunSpec{
				TaskRef: &v1beta1.TaskRef{
					Name:       "taskname",
					APIVersion: "a1",
				},
				ServiceAccountName: "test-sa",
			},
		},
		// taskRun 2
		{
			ObjectMeta: objectMeta("taskrun-example-populated", "foo"),
			Spec: v1beta1.TaskRunSpec{
				TaskRef:            &v1beta1.TaskRef{Name: "unit-test-task"},
				ServiceAccountName: "test-sa",
				Resources:          &v1beta1.TaskRunResources{},
				Timeout:            &metav1.Duration{Duration: config.DefaultTimeoutMinutes * time.Minute},
			},
			Status: v1beta1.TaskRunStatus{
				TaskRunStatusFields: v1beta1.TaskRunStatusFields{
					Steps: []v1beta1.StepState{{
						ContainerState: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{ExitCode: int32(0)},
						},
					}},
				},
			},
		},
		// taskRun 3
		{
			ObjectMeta: objectMeta("taskrun-example-with-objmeta", "foo"),
			Spec: v1beta1.TaskRunSpec{
				TaskRef:            &v1beta1.TaskRef{Name: "unit-test-task"},
				ServiceAccountName: "test-sa",
				Resources:          &v1beta1.TaskRunResources{},
				Timeout:            &metav1.Duration{Duration: config.DefaultTimeoutMinutes * time.Minute},
			},
			Status: v1beta1.TaskRunStatus{
				Status: duckv1beta1.Status{
					Conditions: duckv1beta1.Conditions{
						apis.Condition{
							Type: apis.ConditionSucceeded,
						},
					},
				},
				TaskRunStatusFields: v1beta1.TaskRunStatusFields{
					Steps: []v1beta1.StepState{{
						ContainerState: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{ExitCode: int32(0)},
						},
					}},
				},
			},
		},
		{
			ObjectMeta: objectMeta("taskrun-example-with-objmeta-annotations", "foo"),
			Spec: v1beta1.TaskRunSpec{
				TaskRef:            &v1beta1.TaskRef{Name: "unit-test-task"},
				ServiceAccountName: "test-sa",
				Resources:          &v1beta1.TaskRunResources{},
				Timeout:            &metav1.Duration{Duration: config.DefaultTimeoutMinutes * time.Minute},
			},
			Status: v1beta1.TaskRunStatus{
				Status: duckv1beta1.Status{
					Conditions: duckv1beta1.Conditions{
						apis.Condition{
							Type: apis.ConditionSucceeded,
						},
					},
					Annotations: map[string]string{
						"annotation1": "a1value",
						"annotation2": "a2value",
					},
				},
				TaskRunStatusFields: v1beta1.TaskRunStatusFields{
					Steps: []v1beta1.StepState{{
						ContainerState: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{ExitCode: int32(0)},
						},
					}},
				},
			},
		},
	}
}

func testPipelineResourceResults() []v1beta1.PipelineResourceResult {
	return []v1beta1.PipelineResourceResult{{
		Key:         "digest",
		Value:       "sha256:12345",
		ResourceRef: &v1beta1.PipelineResourceRef{Name: "source-image"},
	}}
}

func getHash(tr *v1beta1.TaskRun) string {
	return tr.Status.Status.Annotations[TaskRunStatusHashAnnotation]
}
