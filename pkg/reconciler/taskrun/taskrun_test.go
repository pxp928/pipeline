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

package taskrun

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"knative.dev/pkg/ptr"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/tektoncd/pipeline/pkg/apis/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/pod"
	resourcev1alpha1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1alpha1"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	podconvert "github.com/tektoncd/pipeline/pkg/pod"
	"github.com/tektoncd/pipeline/pkg/reconciler/events/cloudevent"
	"github.com/tektoncd/pipeline/pkg/reconciler/taskrun/resources"
	ttesting "github.com/tektoncd/pipeline/pkg/reconciler/testing"
	"github.com/tektoncd/pipeline/pkg/reconciler/volumeclaim"
	"github.com/tektoncd/pipeline/pkg/spire"
	spireconfig "github.com/tektoncd/pipeline/pkg/spire/config"
	"github.com/tektoncd/pipeline/test"
	"github.com/tektoncd/pipeline/test/diff"
	eventstest "github.com/tektoncd/pipeline/test/events"
	"github.com/tektoncd/pipeline/test/names"
	"github.com/tektoncd/pipeline/test/parse"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	k8sapierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sruntimeschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/clock"
	fakekubeclientset "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/changeset"
	cminformer "knative.dev/pkg/configmap/informer"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/kmeta"
	"knative.dev/pkg/logging"

	pkgreconciler "knative.dev/pkg/reconciler"
	"knative.dev/pkg/system"

	_ "knative.dev/pkg/system/testing" // Setup system.Namespace()
)

const (
	entrypointLocation = "/tekton/bin/entrypoint"
	workspaceDir       = "/workspace"
	currentAPIVersion  = "tekton.dev/v1beta1"
)

var (
	defaultActiveDeadlineSeconds = int64(config.DefaultTimeoutMinutes * 60 * 1.5)
	images                       = pipeline.Images{
		EntrypointImage:          "override-with-entrypoint:latest",
		NopImage:                 "override-with-nop:latest",
		GitImage:                 "override-with-git:latest",
		KubeconfigWriterImage:    "override-with-kubeconfig-writer:latest",
		ShellImage:               "busybox",
		GsutilImage:              "gcr.io/google.com/cloudsdktool/cloud-sdk",
		PRImage:                  "override-with-pr:latest",
		ImageDigestExporterImage: "override-with-imagedigest-exporter-image:latest",
	}
	spireConfig              = spireconfig.SpireConfig{MockSpire: true}
	now                      = time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)
	ignoreLastTransitionTime = cmpopts.IgnoreFields(apis.Condition{}, "LastTransitionTime.Inner.Time")
	// Pods are created with a random 5-character suffix that we want to
	// ignore in our diffs.
	ignoreRandomPodNameSuffix = cmp.FilterPath(func(path cmp.Path) bool {
		return path.GoString() == "{v1.ObjectMeta}.Name"
	}, cmp.Comparer(func(name1, name2 string) bool {
		return name1[:len(name1)-5] == name2[:len(name2)-5]
	}))
	resourceQuantityCmp = cmp.Comparer(func(x, y resource.Quantity) bool {
		return x.Cmp(y) == 0
	})

	ignoreEnvVarOrdering = cmpopts.SortSlices(func(x, y corev1.EnvVar) bool { return x.Name < y.Name })
	volumeSort           = cmpopts.SortSlices(func(i, j corev1.Volume) bool { return i.Name < j.Name })
	volumeMountSort      = cmpopts.SortSlices(func(i, j corev1.VolumeMount) bool { return i.Name < j.Name })
	cloudEventTarget1    = "https://foo"
	cloudEventTarget2    = "https://bar"

	simpleStep = v1beta1.Step{
		Container: corev1.Container{
			Name:    "simple-step",
			Image:   "foo",
			Command: []string{"/mycmd"},
		},
	}
	simpleTask = &v1beta1.Task{
		ObjectMeta: objectMeta("test-task", "foo"),
		Spec: v1beta1.TaskSpec{
			Steps: []v1beta1.Step{simpleStep},
		},
	}
	simpleTypedTask = &v1beta1.Task{
		ObjectMeta: objectMeta("test-task", "foo"),
		TypeMeta: metav1.TypeMeta{
			APIVersion: "tekton.dev/v1beta1",
			Kind:       "Task",
		},
		Spec: v1beta1.TaskSpec{
			Steps: []v1beta1.Step{simpleStep},
		},
	}

	clustertask = &v1beta1.ClusterTask{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-task"},
		Spec: v1beta1.TaskSpec{
			Steps: []v1beta1.Step{simpleStep},
		},
	}
	taskSidecar = &v1beta1.Task{
		ObjectMeta: objectMeta("test-task-sidecar", "foo"),
		Spec: v1beta1.TaskSpec{
			Sidecars: []v1beta1.Sidecar{{
				Container: corev1.Container{
					Name:  "sidecar",
					Image: "image-id",
				},
			}},
		},
	}
	taskMultipleSidecars = &v1beta1.Task{
		ObjectMeta: objectMeta("test-task-sidecar", "foo"),
		Spec: v1beta1.TaskSpec{
			Sidecars: []v1beta1.Sidecar{
				{
					Container: corev1.Container{
						Name:  "sidecar",
						Image: "image-id",
					},
				},
				{
					Container: corev1.Container{
						Name:  "sidecar2",
						Image: "image-id",
					},
				},
			},
		},
	}

	outputTask = &v1beta1.Task{
		ObjectMeta: metav1.ObjectMeta{Name: "test-output-task"},
		Spec: v1beta1.TaskSpec{
			Steps: []v1beta1.Step{simpleStep},
			Resources: &v1beta1.TaskResources{
				Inputs: []v1beta1.TaskResource{
					{
						ResourceDeclaration: v1beta1.ResourceDeclaration{
							Name: gitResource.Name,
							Type: resourcev1alpha1.PipelineResourceTypeGit,
						},
					},
					{
						ResourceDeclaration: v1beta1.ResourceDeclaration{
							Name: anotherGitResource.Name,
							Type: resourcev1alpha1.PipelineResourceTypeGit,
						},
					},
				},
				Outputs: []v1beta1.TaskResource{{
					ResourceDeclaration: v1beta1.ResourceDeclaration{
						Name: gitResource.Name,
						Type: resourcev1alpha1.PipelineResourceTypeGit,
					},
				}},
			},
		},
	}

	saTask = &v1beta1.Task{
		ObjectMeta: objectMeta("test-with-sa", "foo"),
		Spec: v1beta1.TaskSpec{
			Steps: []v1beta1.Step{{
				Container: corev1.Container{
					Name:    "sa-step",
					Image:   "foo",
					Command: []string{"/mycmd"},
				},
			}},
		},
	}

	templatedTask = &v1beta1.Task{
		ObjectMeta: objectMeta("test-task-with-substitution", "foo"),
		Spec: v1beta1.TaskSpec{
			Params: []v1beta1.ParamSpec{
				{
					Name: "myarg",
					Type: v1beta1.ParamTypeString,
				},
				{
					Name:    "myarghasdefault",
					Type:    v1beta1.ParamTypeString,
					Default: v1beta1.NewArrayOrString("dont see me"),
				},
				{
					Name:    "myarghasdefault2",
					Type:    v1beta1.ParamTypeString,
					Default: v1beta1.NewArrayOrString("thedefault"),
				},
				{
					Name: "configmapname",
					Type: v1beta1.ParamTypeString,
				},
			},
			Resources: &v1beta1.TaskResources{
				Inputs: []v1beta1.TaskResource{{
					ResourceDeclaration: v1beta1.ResourceDeclaration{
						Name: "workspace",
						Type: resourcev1alpha1.PipelineResourceTypeGit,
					},
				}},
				Outputs: []v1beta1.TaskResource{{
					ResourceDeclaration: v1beta1.ResourceDeclaration{
						Name: "myimage",
						Type: resourcev1alpha1.PipelineResourceTypeImage,
					},
				}},
			},
			Steps: []v1beta1.Step{
				{
					Container: corev1.Container{
						Image:   "myimage",
						Name:    "mycontainer",
						Command: []string{"/mycmd"},
						Args: []string{
							"--my-arg=$(inputs.params.myarg)",
							"--my-arg-with-default=$(inputs.params.myarghasdefault)",
							"--my-arg-with-default2=$(inputs.params.myarghasdefault2)",
							"--my-additional-arg=$(outputs.resources.myimage.url)",
							"--my-taskname-arg=$(context.task.name)",
							"--my-taskrun-arg=$(context.taskRun.name)",
						},
					},
				},
				{
					Container: corev1.Container{
						Image:   "myotherimage",
						Name:    "myothercontainer",
						Command: []string{"/mycmd"},
						Args:    []string{"--my-other-arg=$(inputs.resources.workspace.url)"},
					},
				},
			},
			Volumes: []corev1.Volume{{
				Name: "volume-configmap",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "$(inputs.params.configmapname)",
						},
					},
				},
			}},
		},
	}

	twoOutputsTask = &v1beta1.Task{
		ObjectMeta: objectMeta("test-two-output-task", "foo"),
		Spec: v1beta1.TaskSpec{
			Steps: []v1beta1.Step{simpleStep},
			Resources: &v1beta1.TaskResources{
				Outputs: []v1beta1.TaskResource{
					{
						ResourceDeclaration: v1beta1.ResourceDeclaration{
							Name: cloudEventResource.Name,
							Type: resourcev1alpha1.PipelineResourceTypeCloudEvent,
						},
					},
					{
						ResourceDeclaration: v1beta1.ResourceDeclaration{
							Name: anotherCloudEventResource.Name,
							Type: resourcev1alpha1.PipelineResourceTypeCloudEvent,
						},
					},
				},
			},
		},
	}

	gitResource = &resourcev1alpha1.PipelineResource{
		ObjectMeta: objectMeta("git-resource", "foo"),
		Spec: resourcev1alpha1.PipelineResourceSpec{
			Type: resourcev1alpha1.PipelineResourceTypeGit,
			Params: []resourcev1alpha1.ResourceParam{{
				Name:  "URL",
				Value: "https://foo.git",
			}},
		},
	}
	anotherGitResource = &resourcev1alpha1.PipelineResource{
		ObjectMeta: objectMeta("another-git-resource", "foo"),
		Spec: resourcev1alpha1.PipelineResourceSpec{
			Type: resourcev1alpha1.PipelineResourceTypeGit,
			Params: []resourcev1alpha1.ResourceParam{{
				Name:  "URL",
				Value: "https://foobar.git",
			}},
		},
	}
	imageResource = &resourcev1alpha1.PipelineResource{
		ObjectMeta: objectMeta("image-resource", "foo"),
		Spec: resourcev1alpha1.PipelineResourceSpec{
			Type: resourcev1alpha1.PipelineResourceTypeImage,
			Params: []resourcev1alpha1.ResourceParam{{
				Name:  "URL",
				Value: "gcr.io/kristoff/sven",
			}},
		},
	}
	cloudEventResource = &resourcev1alpha1.PipelineResource{
		ObjectMeta: objectMeta("cloud-event-resource", "foo"),
		Spec: resourcev1alpha1.PipelineResourceSpec{
			Type: resourcev1alpha1.PipelineResourceTypeCloudEvent,
			Params: []resourcev1alpha1.ResourceParam{{
				Name:  "TargetURI",
				Value: cloudEventTarget1,
			}},
		},
	}
	anotherCloudEventResource = &resourcev1alpha1.PipelineResource{
		ObjectMeta: objectMeta("another-cloud-event-resource", "foo"),
		Spec: resourcev1alpha1.PipelineResourceSpec{
			Type: resourcev1alpha1.PipelineResourceTypeCloudEvent,
			Params: []resourcev1alpha1.ResourceParam{{
				Name:  "TargetURI",
				Value: cloudEventTarget2,
			}},
		},
	}

	binVolume = corev1.Volume{
		Name: "tekton-internal-bin",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	workspaceVolume = corev1.Volume{
		Name: "tekton-internal-workspace",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	homeVolume = corev1.Volume{
		Name: "tekton-internal-home",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	resultsVolume = corev1.Volume{
		Name: "tekton-internal-results",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	downwardVolume = corev1.Volume{
		Name: "tekton-internal-downward",
		VolumeSource: corev1.VolumeSource{
			DownwardAPI: &corev1.DownwardAPIVolumeSource{
				Items: []corev1.DownwardAPIVolumeFile{{
					Path: "ready",
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.annotations['tekton.dev/ready']",
					},
				}},
			},
		},
	}
	stepsVolume = corev1.Volume{
		Name: "tekton-internal-steps",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	placeToolsInitContainer = corev1.Container{
		Command: []string{"/ko-app/entrypoint", "cp", "/ko-app/entrypoint", entrypointLocation},
		VolumeMounts: []corev1.VolumeMount{{
			MountPath: "/tekton/bin",
			Name:      "tekton-internal-bin",
		}},
		WorkingDir: "/",
		Name:       "place-tools",
		Image:      "override-with-entrypoint:latest",
	}
	fakeVersion                string
	gitResourceSecurityContext = &corev1.SecurityContext{
		RunAsUser: ptr.Int64(0),
	}
)

var testClock = clock.NewFakePassiveClock(now)

func runVolume(i int) corev1.Volume {
	return corev1.Volume{
		Name: fmt.Sprintf("tekton-internal-run-%d", i),
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
}

func createServiceAccount(t *testing.T, assets test.Assets, name string, namespace string) {
	t.Helper()
	if _, err := assets.Clients.Kube.CoreV1().ServiceAccounts(namespace).Create(assets.Ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func init() {
	os.Setenv("KO_DATA_PATH", "./testdata/")
	commit, err := changeset.Get()
	if err != nil {
		panic(err)
	}
	fakeVersion = commit
}

func getRunName(tr *v1beta1.TaskRun) string {
	return strings.Join([]string{tr.Namespace, tr.Name}, "/")
}

func ensureConfigurationConfigMapsExist(d *test.Data) {
	var defaultsExists, featureFlagsExists, artifactBucketExists, artifactPVCExists, metricsExists bool
	for _, cm := range d.ConfigMaps {
		if cm.Name == config.GetDefaultsConfigName() {
			defaultsExists = true
		}
		if cm.Name == config.GetFeatureFlagsConfigName() {
			featureFlagsExists = true
		}
		if cm.Name == config.GetArtifactBucketConfigName() {
			artifactBucketExists = true
		}
		if cm.Name == config.GetArtifactPVCConfigName() {
			artifactPVCExists = true
		}
		if cm.Name == config.GetMetricsConfigName() {
			metricsExists = true
		}
	}
	if !defaultsExists {
		d.ConfigMaps = append(d.ConfigMaps, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: config.GetDefaultsConfigName(), Namespace: system.Namespace()},
			Data:       map[string]string{},
		})
	}
	if !featureFlagsExists {
		d.ConfigMaps = append(d.ConfigMaps, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: config.GetFeatureFlagsConfigName(), Namespace: system.Namespace()},
			Data:       map[string]string{},
		})
	}
	if !artifactBucketExists {
		d.ConfigMaps = append(d.ConfigMaps, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: config.GetArtifactBucketConfigName(), Namespace: system.Namespace()},
			Data:       map[string]string{},
		})
	}
	if !artifactPVCExists {
		d.ConfigMaps = append(d.ConfigMaps, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: config.GetArtifactPVCConfigName(), Namespace: system.Namespace()},
			Data:       map[string]string{},
		})
	}
	if !metricsExists {
		d.ConfigMaps = append(d.ConfigMaps, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: config.GetMetricsConfigName(), Namespace: system.Namespace()},
			Data:       map[string]string{},
		})
	}
}

// getTaskRunController returns an instance of the TaskRun controller/reconciler that has been seeded with
// d, where d represents the state of the system (existing resources) needed for the test.
func getTaskRunController(t *testing.T, d test.Data) (test.Assets, func()) {
	t.Helper()
	names.TestingSeed()
	return initializeTaskRunControllerAssets(t, d, pipeline.Options{Images: images, SpireConfig: spireConfig})
}

func initializeTaskRunControllerAssets(t *testing.T, d test.Data, opts pipeline.Options) (test.Assets, func()) {
	ctx, _ := ttesting.SetupFakeContext(t)
	ctx, cancel := context.WithCancel(ctx)
	ensureConfigurationConfigMapsExist(&d)
	c, informers := test.SeedTestData(t, ctx, d)
	configMapWatcher := cminformer.NewInformedWatcher(c.Kube, system.Namespace())
	ctl := NewController(&opts, testClock)(ctx, configMapWatcher)
	if err := configMapWatcher.Start(ctx.Done()); err != nil {
		t.Fatalf("error starting configmap watcher: %v", err)
	}

	if la, ok := ctl.Reconciler.(pkgreconciler.LeaderAware); ok {
		la.Promote(pkgreconciler.UniversalBucket(), func(pkgreconciler.Bucket, types.NamespacedName) {})
	}

	return test.Assets{
		Logger:     logging.FromContext(ctx),
		Controller: ctl,
		Clients:    c,
		Informers:  informers,
		Recorder:   controller.GetEventRecorder(ctx).(*record.FakeRecorder),
		Ctx:        ctx,
	}, cancel
}

func TestReconcile_ExplicitDefaultSA(t *testing.T) {
	taskRunSuccess := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-success
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task
`)
	taskRunWithSaSuccess := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-with-sa-run-success
  namespace: foo
spec:
  serviceAccountName: test-sa
  taskRef:
    apiVersion: a1
    name: test-with-sa
`)
	taskruns := []*v1beta1.TaskRun{taskRunSuccess, taskRunWithSaSuccess}
	defaultSAName := "pipelines"
	d := test.Data{
		TaskRuns: taskruns,
		Tasks:    []*v1beta1.Task{simpleTask, saTask},
		ConfigMaps: []*corev1.ConfigMap{
			{
				ObjectMeta: metav1.ObjectMeta{Name: config.GetDefaultsConfigName(), Namespace: system.Namespace()},
				Data: map[string]string{
					"default-service-account":        defaultSAName,
					"default-timeout-minutes":        "60",
					"default-managed-by-label-value": "tekton-pipelines",
				},
			},
		},
	}
	for _, tc := range []struct {
		name    string
		taskRun *v1beta1.TaskRun
		wantPod *corev1.Pod
	}{{
		name:    "success",
		taskRun: taskRunSuccess,
		wantPod: expectedPod("test-taskrun-run-success-pod", "test-task", "test-taskrun-run-success", "foo", defaultSAName, false, nil, []stepForExpectedPod{{
			image: "foo",
			name:  "simple-step",
			cmd:   "/mycmd",
		}}),
	}, {
		name:    "serviceaccount",
		taskRun: taskRunWithSaSuccess,
		wantPod: expectedPod("test-taskrun-with-sa-run-success-pod", "test-with-sa", "test-taskrun-with-sa-run-success", "foo", "test-sa", false, nil, []stepForExpectedPod{{
			image: "foo",
			name:  "sa-step",
			cmd:   "/mycmd",
		}}),
	}} {
		t.Run(tc.name, func(t *testing.T) {
			saName := tc.taskRun.Spec.ServiceAccountName
			if saName == "" {
				saName = defaultSAName
			}
			d.ServiceAccounts = append(d.ServiceAccounts, &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      saName,
					Namespace: tc.taskRun.Namespace,
				},
			})
			testAssets, cancel := getTaskRunController(t, d)
			defer cancel()
			c := testAssets.Controller
			clients := testAssets.Clients

			if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tc.taskRun)); err == nil {
				t.Error("Wanted a wrapped requeue error, but got nil.")
			} else if ok, _ := controller.IsRequeueKey(err); !ok {
				t.Errorf("expected no error. Got error %v", err)
			}
			if len(clients.Kube.Actions()) == 0 {
				t.Errorf("Expected actions to be logged in the kubeclient, got none")
			}

			tr, err := clients.Pipeline.TektonV1beta1().TaskRuns(tc.taskRun.Namespace).Get(testAssets.Ctx, tc.taskRun.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("getting updated taskrun: %v", err)
			}
			condition := tr.Status.GetCondition(apis.ConditionSucceeded)
			if condition == nil || condition.Status != corev1.ConditionUnknown {
				t.Errorf("Expected invalid TaskRun to have in progress status, but had %v", condition)
			}
			if condition != nil && condition.Reason != v1beta1.TaskRunReasonRunning.String() {
				t.Errorf("Expected reason %q but was %s", v1beta1.TaskRunReasonRunning.String(), condition.Reason)
			}

			if tr.Status.PodName == "" {
				t.Fatalf("Reconcile didn't set pod name")
			}

			pod, err := clients.Kube.CoreV1().Pods(tr.Namespace).Get(testAssets.Ctx, tr.Status.PodName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Failed to fetch build pod: %v", err)
			}

			if d := cmp.Diff(tc.wantPod.ObjectMeta, pod.ObjectMeta, ignoreRandomPodNameSuffix); d != "" {
				t.Errorf("Pod metadata doesn't match %s", diff.PrintWantGot(d))
			}

			if d := cmp.Diff(tc.wantPod.Spec, pod.Spec, resourceQuantityCmp, volumeSort, volumeMountSort, ignoreEnvVarOrdering); d != "" {
				t.Errorf("Pod spec doesn't match, %s", diff.PrintWantGot(d))
			}
			if len(clients.Kube.Actions()) == 0 {
				t.Fatalf("Expected actions to be logged in the kubeclient, got none")
			}
		})
	}
}

// TestReconcile_CloudEvents runs reconcile with a cloud event sink configured
// to ensure that events are sent in different cases
func TestReconcile_CloudEvents(t *testing.T) {
	task := parse.MustParseTask(t, `
metadata:
  name: test-task
  namespace: foo
spec:
  steps:
  - command:
    - /mycmd
    env:
    - name: foo
      value: bar
    image: foo
    name: simple-step
`)
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-not-started
  namespace: foo
  selfLink: /test/taskrun1
spec:
  taskRef:
    name: test-task
`)
	d := test.Data{
		Tasks:    []*v1beta1.Task{task},
		TaskRuns: []*v1beta1.TaskRun{taskRun},
	}

	d.ConfigMaps = []*corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{Name: config.GetDefaultsConfigName(), Namespace: system.Namespace()},
			Data: map[string]string{
				"default-cloud-events-sink": "http://synk:8080",
			},
		},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients
	saName := "default"
	if _, err := clients.Kube.CoreV1().ServiceAccounts(taskRun.Namespace).Create(testAssets.Ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: taskRun.Namespace,
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err == nil {
		t.Error("Wanted a wrapped requeue error, but got nil.")
	} else if ok, _ := controller.IsRequeueKey(err); !ok {
		t.Errorf("expected no error. Got error %v", err)
	}
	if len(clients.Kube.Actions()) == 0 {
		t.Errorf("Expected actions to be logged in the kubeclient, got none")
	}

	tr, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting updated taskrun: %v", err)
	}
	condition := tr.Status.GetCondition(apis.ConditionSucceeded)
	if condition == nil || condition.Status != corev1.ConditionUnknown {
		t.Errorf("Expected fresh TaskRun to have in progress status, but had %v", condition)
	}
	if condition != nil && condition.Reason != v1beta1.TaskRunReasonRunning.String() {
		t.Errorf("Expected reason %q but was %s", v1beta1.TaskRunReasonRunning.String(), condition.Reason)
	}

	wantEvents := []string{
		"Normal Start",
		"Normal Running",
	}
	err = eventstest.CheckEventsOrdered(t, testAssets.Recorder.Events, "reconcile-cloud-events", wantEvents)
	if !(err == nil) {
		t.Errorf(err.Error())
	}

	wantCloudEvents := []string{
		`(?s)dev.tekton.event.taskrun.started.v1.*test-taskrun-not-started`,
		`(?s)dev.tekton.event.taskrun.running.v1.*test-taskrun-not-started`,
	}
	ceClient := clients.CloudEvents.(cloudevent.FakeClient)
	err = eventstest.CheckEventsUnordered(t, ceClient.Events, "reconcile-cloud-events", wantCloudEvents)
	if !(err == nil) {
		t.Errorf(err.Error())
	}
}

func TestReconcile(t *testing.T) {
	taskRunSuccess := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-success
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task
`)
	taskRunWithSaSuccess := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-with-sa-run-success
  namespace: foo
spec:
  serviceAccountName: test-sa
  taskRef:
    apiVersion: a1
    name: test-with-sa
`)
	taskRunSubstitution := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-substitution
  namespace: foo
spec:
  params:
  - name: myarg
    value: foo
  - name: myarghasdefault
    value: bar
  - name: configmapname
    value: configbar
  resources:
    inputs:
    - name: workspace
      resourceRef:
        name: git-resource
    outputs:
    - name: myimage
      resourceRef:
        name: image-resource
  taskRef:
    apiVersion: a1
    name: test-task-with-substitution
`)
	taskRunInputOutput := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-input-output
  namespace: foo
  ownerReferences:
  - kind: PipelineRun
    name: test
spec:
  resources:
    inputs:
    - name: git-resource
      paths:
      - source-folder
      resourceRef:
        name: git-resource
    - name: another-git-resource
      paths:
      - source-folder
      resourceRef:
        name: another-git-resource
    outputs:
    - name: git-resource
      paths:
      - output-folder
      resourceRef:
        name: git-resource
  taskRef:
    name: test-output-task
`)
	taskRunWithTaskSpec := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-with-taskspec
  namespace: foo
spec:
  params:
  - name: myarg
    value: foo
  resources:
    inputs:
    - name: workspace
      resourceRef:
        name: git-resource
  taskSpec:
    params:
    - default: mydefault
      name: myarg
      type: string
    resources:
      inputs:
      - name: workspace
        type: git
    steps:
    - args:
      - --my-arg=$(inputs.params.myarg)
      command:
      - /mycmd
      image: myimage
      name: mycontainer
`)

	taskRunWithResourceSpecAndTaskSpec := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-with-resource-spec
  namespace: foo
spec:
  resources:
    inputs:
    - name: workspace
      resourceSpec:
        params:
        - name: URL
          value: github.com/foo/bar.git
        - name: revision
          value: rel-can
        type: git
  taskSpec:
    resources:
      inputs:
      - name: workspace
        type: git
    steps:
    - command:
      - /mycmd
      image: ubuntu
      name: mystep
`)

	taskRunWithClusterTask := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-with-cluster-task
  namespace: foo
spec:
  taskRef:
    kind: ClusterTask
    name: test-cluster-task
`)

	taskRunWithLabels := parse.MustParseTaskRun(t, `
metadata:
  labels:
    TaskRunLabel: TaskRunValue
    tekton.dev/taskRun: WillNotBeUsed
  name: test-taskrun-with-labels
  namespace: foo
spec:
  taskRef:
    name: test-task
`)

	taskRunWithAnnotations := parse.MustParseTaskRun(t, `
metadata:
  annotations:
    TaskRunAnnotation: TaskRunValue
  name: test-taskrun-with-annotations
  namespace: foo
spec:
  taskRef:
    name: test-task
`)

	taskRunWithPod := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-with-pod
  namespace: foo
spec:
  taskRef:
    name: test-task
status:
  podName: some-pod-abcdethat-no-longer-exists
`)

	taskRunWithCredentialsVariable := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-with-credentials-variable
  namespace: foo
spec:
  taskSpec:
    steps:
    - command:
      - /mycmd $(credentials.path)
      image: myimage
      name: mycontainer
`)

	// Set up a fake registry to push an image to.
	s := httptest.NewServer(registry.New())
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Upload the simple task to the registry for our taskRunBundle TaskRun.
	ref, err := test.CreateImage(u.Host+"/"+simpleTypedTask.Name, simpleTypedTask)
	if err != nil {
		t.Fatalf("failed to upload image with simple task: %s", err.Error())
	}

	taskRunBundle := parse.MustParseTaskRun(t, fmt.Sprintf(`
metadata:
  name: test-taskrun-bundle
  namespace: foo
spec:
  taskRef:
    bundle: %s
    name: test-task
`, ref))

	taskruns := []*v1beta1.TaskRun{
		taskRunSuccess, taskRunWithSaSuccess,
		taskRunSubstitution, taskRunInputOutput,
		taskRunWithTaskSpec, taskRunWithClusterTask, taskRunWithResourceSpecAndTaskSpec,
		taskRunWithLabels, taskRunWithAnnotations, taskRunWithPod,
		taskRunWithCredentialsVariable, taskRunBundle,
	}

	d := test.Data{
		TaskRuns:          taskruns,
		Tasks:             []*v1beta1.Task{simpleTask, saTask, templatedTask, outputTask},
		ClusterTasks:      []*v1beta1.ClusterTask{clustertask},
		PipelineResources: []*resourcev1alpha1.PipelineResource{gitResource, anotherGitResource, imageResource},
	}
	for _, tc := range []struct {
		name       string
		taskRun    *v1beta1.TaskRun
		wantPod    *corev1.Pod
		wantEvents []string
	}{{
		name:    "success",
		taskRun: taskRunSuccess,
		wantEvents: []string{
			"Normal Started ",
			"Normal Running Not all Steps",
		},
		wantPod: expectedPod("test-taskrun-run-success-pod", "test-task", "test-taskrun-run-success", "foo", config.DefaultServiceAccountValue, false, nil, []stepForExpectedPod{{
			image: "foo",
			name:  "simple-step",
			cmd:   "/mycmd",
		}}),
	}, {
		name:    "serviceaccount",
		taskRun: taskRunWithSaSuccess,
		wantEvents: []string{
			"Normal Started ",
			"Normal Running Not all Steps",
		},
		wantPod: expectedPod("test-taskrun-with-sa-run-success-pod", "test-with-sa", "test-taskrun-with-sa-run-success", "foo", "test-sa", false, nil, []stepForExpectedPod{{
			image: "foo",
			name:  "sa-step",
			cmd:   "/mycmd",
		}}),
	}, {
		name:    "params",
		taskRun: taskRunSubstitution,
		wantEvents: []string{
			"Normal Started ",
			"Normal Running Not all Steps",
		},
		wantPod: expectedPod("test-taskrun-substitution-pod", "test-task-with-substitution", "test-taskrun-substitution", "foo", config.DefaultServiceAccountValue, false, []corev1.Volume{{
			Name: "volume-configmap",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "configbar",
					},
				},
			},
		}}, []stepForExpectedPod{
			{
				name:  "create-dir-myimage-mssqb",
				image: "busybox",
				cmd:   "mkdir",
				args:  []string{"-p", "/workspace/output/myimage"},
			},
			{
				name:  "git-source-workspace-mz4c7",
				image: "override-with-git:latest",
				cmd:   "/ko-app/git-init",
				args: []string{"-url", "https://foo.git",
					"-path", "/workspace/workspace"},
				envVars: map[string]string{
					"TEKTON_RESOURCE_NAME": "workspace",
					"HOME":                 "/tekton/home",
				},
				workingDir:      workspaceDir,
				securityContext: gitResourceSecurityContext,
			},
			{
				name:  "mycontainer",
				image: "myimage",
				cmd:   "/mycmd",
				args: []string{
					"--my-arg=foo",
					"--my-arg-with-default=bar",
					"--my-arg-with-default2=thedefault",
					"--my-additional-arg=gcr.io/kristoff/sven",
					"--my-taskname-arg=test-task-with-substitution",
					"--my-taskrun-arg=test-taskrun-substitution",
				},
			},
			{
				name:  "myothercontainer",
				image: "myotherimage",
				cmd:   "/mycmd",
				args:  []string{"--my-other-arg=https://foo.git"},
			},
			{
				name:  "image-digest-exporter-9l9zj",
				image: "override-with-imagedigest-exporter-image:latest",
				cmd:   "/ko-app/imagedigestexporter",
				args: []string{
					"-images",
					"[{\"name\":\"myimage\",\"type\":\"image\",\"url\":\"gcr.io/kristoff/sven\",\"digest\":\"\",\"OutputImageDir\":\"/workspace/output/myimage\"}]",
				},
			},
		}),
	}, {
		name:    "taskrun-with-taskspec",
		taskRun: taskRunWithTaskSpec,
		wantEvents: []string{
			"Normal Started ",
			"Normal Running Not all Steps",
		},
		wantPod: expectedPod("test-taskrun-with-taskspec-pod", "", "test-taskrun-with-taskspec", "foo", config.DefaultServiceAccountValue, false, nil, []stepForExpectedPod{
			{
				name:  "git-source-workspace-9l9zj",
				image: "override-with-git:latest",
				cmd:   "/ko-app/git-init",
				args: []string{"-url", "https://foo.git",
					"-path", "/workspace/workspace"},
				envVars: map[string]string{
					"TEKTON_RESOURCE_NAME": "workspace",
					"HOME":                 "/tekton/home",
				},
				workingDir:      workspaceDir,
				securityContext: gitResourceSecurityContext,
			},
			{
				name:  "mycontainer",
				image: "myimage",
				cmd:   "/mycmd",
				args: []string{
					"--my-arg=foo",
				},
			},
		}),
	}, {
		name:    "success-with-cluster-task",
		taskRun: taskRunWithClusterTask,
		wantEvents: []string{
			"Normal Started ",
			"Normal Running Not all Steps",
		},
		wantPod: expectedPod("test-taskrun-with-cluster-task-pod", "test-cluster-task", "test-taskrun-with-cluster-task", "foo", config.DefaultServiceAccountValue, true, nil, []stepForExpectedPod{{
			name:  "simple-step",
			image: "foo",
			cmd:   "/mycmd",
		}}),
	}, {
		name:    "taskrun-with-resource-spec-task-spec",
		taskRun: taskRunWithResourceSpecAndTaskSpec,
		wantEvents: []string{
			"Normal Started ",
			"Normal Running Not all Steps",
		},
		wantPod: expectedPod("test-taskrun-with-resource-spec-pod", "", "test-taskrun-with-resource-spec", "foo", config.DefaultServiceAccountValue, false, nil, []stepForExpectedPod{
			{
				name:  "git-source-workspace-9l9zj",
				image: "override-with-git:latest",
				cmd:   "/ko-app/git-init",
				args: []string{"-url", "github.com/foo/bar.git",
					"-path", "/workspace/workspace",
					"-revision", "rel-can",
				},
				envVars: map[string]string{
					"TEKTON_RESOURCE_NAME": "workspace",
					"HOME":                 "/tekton/home",
				},
				workingDir:      workspaceDir,
				securityContext: gitResourceSecurityContext,
			},
			{
				name:  "mystep",
				image: "ubuntu",
				cmd:   "/mycmd",
			},
		}),
	}, {
		name:    "taskrun-with-pod",
		taskRun: taskRunWithPod,
		wantEvents: []string{
			"Normal Started ",
			"Normal Running Not all Steps",
		},
		wantPod: expectedPod("test-taskrun-with-pod-pod", "test-task", "test-taskrun-with-pod", "foo", config.DefaultServiceAccountValue, false, nil, []stepForExpectedPod{{
			name:  "simple-step",
			image: "foo",
			cmd:   "/mycmd",
		}}),
	}, {
		name:    "taskrun-with-credentials-variable-default-tekton-creds",
		taskRun: taskRunWithCredentialsVariable,
		wantEvents: []string{
			"Normal Started ",
			"Normal Running Not all Steps",
		},
		wantPod: expectedPod("test-taskrun-with-credentials-variable-pod", "", "test-taskrun-with-credentials-variable", "foo", config.DefaultServiceAccountValue, false, nil, []stepForExpectedPod{{
			name:  "mycontainer",
			image: "myimage",
			cmd:   "/mycmd /tekton/creds",
		}}),
	}, {
		name:    "remote-task",
		taskRun: taskRunBundle,
		wantEvents: []string{
			"Normal Started ",
			"Normal Running Not all Steps",
		},
		wantPod: expectedPod("test-taskrun-bundle-pod", "test-task", "test-taskrun-bundle", "foo", config.DefaultServiceAccountValue, false, nil, []stepForExpectedPod{{
			name:  "simple-step",
			image: "foo",
			cmd:   "/mycmd",
		}}),
	}} {
		t.Run(tc.name, func(t *testing.T) {
			testAssets, cancel := getTaskRunController(t, d)
			defer cancel()
			c := testAssets.Controller
			clients := testAssets.Clients
			saName := tc.taskRun.Spec.ServiceAccountName
			if saName == "" {
				saName = "default"
			}
			createServiceAccount(t, testAssets, saName, tc.taskRun.Namespace)

			if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tc.taskRun)); err == nil {
				t.Error("Wanted a wrapped requeue error, but got nil.")
			} else if ok, _ := controller.IsRequeueKey(err); !ok {
				t.Errorf("expected no error. Got error %v", err)
			}
			if len(clients.Kube.Actions()) == 0 {
				t.Errorf("Expected actions to be logged in the kubeclient, got none")
			}

			tr, err := clients.Pipeline.TektonV1beta1().TaskRuns(tc.taskRun.Namespace).Get(testAssets.Ctx, tc.taskRun.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("getting updated taskrun: %v", err)
			}
			condition := tr.Status.GetCondition(apis.ConditionSucceeded)
			if condition == nil || condition.Status != corev1.ConditionUnknown {
				t.Errorf("Expected invalid TaskRun to have in progress status, but had %v", condition)
			}
			if condition != nil && condition.Reason != v1beta1.TaskRunReasonRunning.String() {
				t.Errorf("Expected reason %q but was %s", v1beta1.TaskRunReasonRunning.String(), condition.Reason)
			}

			if tr.Status.PodName == "" {
				t.Fatalf("Reconcile didn't set pod name")
			}

			pod, err := clients.Kube.CoreV1().Pods(tr.Namespace).Get(testAssets.Ctx, tr.Status.PodName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Failed to fetch build pod: %v", err)
			}

			if d := cmp.Diff(tc.wantPod.ObjectMeta, pod.ObjectMeta, ignoreRandomPodNameSuffix); d != "" {
				t.Errorf("Pod metadata doesn't match %s", diff.PrintWantGot(d))
			}

			pod.Name = tc.wantPod.Name // Ignore pod name differences, the pod name is generated and tested in pod_test.go
			if d := cmp.Diff(tc.wantPod.Spec, pod.Spec, resourceQuantityCmp, volumeSort, volumeMountSort, ignoreEnvVarOrdering); d != "" {
				t.Errorf("Pod spec doesn't match %s", diff.PrintWantGot(d))
			}
			if len(clients.Kube.Actions()) == 0 {
				t.Fatalf("Expected actions to be logged in the kubeclient, got none")
			}

			err = eventstest.CheckEventsOrdered(t, testAssets.Recorder.Events, tc.name, tc.wantEvents)
			if err != nil {
				t.Errorf(err.Error())
			}
		})
	}
}

func TestReconcile_SetsStartTime(t *testing.T) {
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun
  namespace: foo
spec:
  taskRef:
    name: test-task
`)
	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{simpleTask},
	}
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	createServiceAccount(t, testAssets, "default", "foo")

	if err := testAssets.Controller.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err == nil {
		t.Error("Wanted a wrapped requeue error, but got nil.")
	} else if ok, _ := controller.IsRequeueKey(err); !ok {
		t.Errorf("expected no error reconciling valid TaskRun but got %v", err)
	}

	newTr, err := testAssets.Clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Expected TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}
	if newTr.Status.StartTime == nil || newTr.Status.StartTime.IsZero() {
		t.Errorf("expected startTime to be set by reconcile but was %q", newTr.Status.StartTime)
	}
}

func TestReconcile_DoesntChangeStartTime(t *testing.T) {
	startTime := time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC)
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun
  namespace: foo
spec:
  taskRef:
    name: test-task
status:
  podName: the-pod
`)
	taskRun.Status.StartTime = &metav1.Time{Time: startTime}
	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{simpleTask},
		Pods: []*corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "foo",
				Name:      "the-pod",
			},
		}},
	}
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()

	if err := testAssets.Controller.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err != nil {
		t.Errorf("expected no error reconciling valid TaskRun but got %v", err)
	}

	if taskRun.Status.StartTime.Time != startTime {
		t.Errorf("expected startTime %q to be preserved by reconcile but was %q", startTime, taskRun.Status.StartTime)
	}
}

func TestReconcileInvalidTaskRuns(t *testing.T) {
	noTaskRun := parse.MustParseTaskRun(t, `
metadata:
  name: notaskrun
  namespace: foo
spec:
  taskRef:
    name: notask
`)
	withWrongRef := parse.MustParseTaskRun(t, `
metadata:
  name: taskrun-with-wrong-ref
  namespace: foo
spec:
  taskRef:
    kind: ClusterTask
    name: taskrun-with-wrong-ref
`)
	taskRuns := []*v1beta1.TaskRun{noTaskRun, withWrongRef}
	tasks := []*v1beta1.Task{simpleTask}

	d := test.Data{
		TaskRuns: taskRuns,
		Tasks:    tasks,
	}

	testcases := []struct {
		name       string
		taskRun    *v1beta1.TaskRun
		reason     string
		wantEvents []string
	}{{
		name:    "task run with no task",
		taskRun: noTaskRun,
		reason:  podconvert.ReasonFailedResolution,
		wantEvents: []string{
			"Normal Started",
			"Warning Failed",
			"Warning InternalError",
		},
	}, {
		name:    "task run with wrong ref",
		taskRun: withWrongRef,
		reason:  podconvert.ReasonFailedResolution,
		wantEvents: []string{
			"Normal Started",
			"Warning Failed",
			"Warning InternalError",
		},
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			testAssets, cancel := getTaskRunController(t, d)
			defer cancel()
			c := testAssets.Controller
			clients := testAssets.Clients
			reconcileErr := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tc.taskRun))

			// When a TaskRun is invalid and can't run, we return a permanent error because
			// a regular error will tell the Reconciler to keep trying to reconcile; instead we want to stop
			// and forget about the Run.
			if reconcileErr == nil {
				t.Fatalf("Expected to see error when reconciling invalid TaskRun but none")
			}
			if !controller.IsPermanentError(reconcileErr) {
				t.Fatalf("Expected to see a permanent error when reconciling invalid TaskRun, got %s instead", reconcileErr)
			}

			// Check actions and events
			actions := clients.Kube.Actions()
			if len(actions) != 2 {
				t.Errorf("expected 2 actions, got %d. Actions: %#v", len(actions), actions)
			}

			err := eventstest.CheckEventsOrdered(t, testAssets.Recorder.Events, tc.name, tc.wantEvents)
			if !(err == nil) {
				t.Errorf(err.Error())
			}

			newTr, err := testAssets.Clients.Pipeline.TektonV1beta1().TaskRuns(tc.taskRun.Namespace).Get(testAssets.Ctx, tc.taskRun.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Expected TaskRun %s to exist but instead got error when getting it: %v", tc.taskRun.Name, err)
			}
			// Since the TaskRun is invalid, the status should say it has failed
			condition := newTr.Status.GetCondition(apis.ConditionSucceeded)
			if condition == nil || condition.Status != corev1.ConditionFalse {
				t.Errorf("Expected invalid TaskRun to have failed status, but had %v", condition)
			}
			if condition != nil && condition.Reason != tc.reason {
				t.Errorf("Expected failure to be because of reason %q but was %s", tc.reason, condition.Reason)
			}
		})
	}

}

func TestReconcileGetTaskError(t *testing.T) {
	tr := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-success
  namespace: foo
spec:
  taskRef:
    name: test-task
`)
	d := test.Data{
		TaskRuns:          []*v1beta1.TaskRun{tr},
		Tasks:             []*v1beta1.Task{simpleTask},
		ClusterTasks:      []*v1beta1.ClusterTask{},
		PipelineResources: []*resourcev1alpha1.PipelineResource{},
	}
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients
	createServiceAccount(t, testAssets, "default", tr.Namespace)

	failingReactorActivated := true
	clients.Pipeline.PrependReactor("*", "tasks", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
		return failingReactorActivated, &v1beta1.Task{}, errors.New("etcdserver: leader changed")
	})
	err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tr))
	if err == nil {
		t.Error("Wanted a wrapped error, but got nil.")
	}
	if controller.IsPermanentError(err) {
		t.Errorf("Unexpected permanent error %v", err)
	}

	failingReactorActivated = false
	err = c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tr))
	if err != nil {
		if ok, _ := controller.IsRequeueKey(err); !ok {
			t.Errorf("unexpected error in TaskRun reconciliation: %v", err)
		}
	}
	reconciledRun, err := clients.Pipeline.TektonV1beta1().TaskRuns("foo").Get(testAssets.Ctx, tr.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Somehow had error getting reconciled run out of fake client: %s", err)
	}
	condition := reconciledRun.Status.GetCondition(apis.ConditionSucceeded)
	if !condition.IsUnknown() {
		t.Errorf("Expected TaskRun to still be running but succeeded condition is %v", condition.Status)
	}
}

func TestReconcileTaskRunWithPermanentError(t *testing.T) {
	noTaskRun := parse.MustParseTaskRun(t, `
metadata:
  name: notaskrun
  namespace: foo
spec:
  taskRef:
    name: notask
status:
  conditions:
  - message: 'error when listing tasks for taskRun taskrun-failure: tasks.tekton.dev
      "notask" not found'
    reason: TaskRunResolutionFailed
    status: "False"
    type: Succeeded
  startTime: "2022-01-01T00:00:00Z"
`)

	taskRuns := []*v1beta1.TaskRun{noTaskRun}
	d := test.Data{
		TaskRuns: taskRuns,
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients
	reconcileErr := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(noTaskRun))

	// When a TaskRun was rejected with a permanent error, reconciler must stop and forget about the run
	// Such TaskRun enters Reconciler and from within the isDone block, marks the run success so that
	// reconciler does not keep trying to reconcile
	if reconcileErr != nil {
		t.Fatalf("Expected to see no error when reconciling TaskRun with Permanent Error but was not none")
	}

	// Check actions
	actions := clients.Kube.Actions()
	if len(actions) != 2 || !actions[0].Matches("list", "configmaps") || !actions[1].Matches("watch", "configmaps") {
		t.Errorf("expected 2 actions (list configmaps, and watch configmaps) created by the reconciler,"+
			" got %d. Actions: %#v", len(actions), actions)
	}

	newTr, err := clients.Pipeline.TektonV1beta1().TaskRuns(noTaskRun.Namespace).Get(context.Background(), noTaskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Expected TaskRun %s to exist but instead got error when getting it: %v", noTaskRun.Name, err)
	}

	// Since the TaskRun is invalid, the status should say it has failed
	condition := newTr.Status.GetCondition(apis.ConditionSucceeded)
	if condition == nil || condition.Status != corev1.ConditionFalse {
		t.Errorf("Expected invalid TaskRun to have failed status, but had %v", condition)
	}
	if condition != nil && condition.Reason != podconvert.ReasonFailedResolution {
		t.Errorf("Expected failure to be because of reason %q but was %s", podconvert.ReasonFailedResolution, condition.Reason)
	}
}

func TestReconcilePodFetchError(t *testing.T) {
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-success
  namespace: foo
spec:
  taskRef:
    name: test-task
status:
  podName: will-not-be-found
`)
	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{simpleTask},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients

	clients.Kube.PrependReactor("get", "pods", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, errors.New("induce failure fetching pods")
	})

	if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err == nil {
		t.Fatal("expected error when reconciling a Task for which we couldn't get the corresponding Pod but got nil")
	}
}

func makePod(taskRun *v1beta1.TaskRun, task *v1beta1.Task) (*corev1.Pod, error) {
	// TODO(jasonhall): This avoids a circular dependency where
	// getTaskRunController takes a test.Data which must be populated with
	// a pod created from MakePod which requires a (fake) Kube client. When
	// we remove Build entirely from this controller, we should simply
	// specify the Pod we want to exist directly, and not call MakePod from
	// the build. This will break the cycle and allow us to simply use
	// clients normally.
	kubeclient := fakekubeclientset.NewSimpleClientset(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: taskRun.Namespace,
		},
	})

	entrypointCache, err := podconvert.NewEntrypointCache(kubeclient)
	if err != nil {
		return nil, err
	}

	builder := podconvert.Builder{
		Images:          images,
		KubeClient:      kubeclient,
		EntrypointCache: entrypointCache,
	}
	return builder.Build(context.Background(), taskRun, task.Spec)
}

func TestReconcilePodUpdateStatus(t *testing.T) {
	const taskLabel = "test-task"
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-success
  namespace: foo
spec:
  taskRef:
    name: test-task
status:
  podName: test-taskrun-run-success-pod
`)

	pod, err := makePod(taskRun, simpleTask)
	if err != nil {
		t.Fatalf("MakePod: %v", err)
	}
	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{simpleTask},
		Pods:     []*corev1.Pod{pod},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients

	if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err == nil {
		t.Error("Wanted a wrapped requeue error, but got nil.")
	} else if ok, _ := controller.IsRequeueKey(err); !ok {
		t.Fatalf("Unexpected error when Reconcile() : %v", err)
	}
	newTr, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Expected TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}
	if d := cmp.Diff(&apis.Condition{
		Type:    apis.ConditionSucceeded,
		Status:  corev1.ConditionUnknown,
		Reason:  v1beta1.TaskRunReasonRunning.String(),
		Message: "Not all Steps in the Task have finished executing",
	}, newTr.Status.GetCondition(apis.ConditionSucceeded), ignoreLastTransitionTime); d != "" {
		t.Fatalf("Did not get expected condition %s", diff.PrintWantGot(d))
	}

	trLabel, ok := newTr.ObjectMeta.Labels[pipeline.TaskLabelKey]
	if !ok {
		t.Errorf("Labels were not added to task run")
	}
	if ld := cmp.Diff(taskLabel, trLabel); ld != "" {
		t.Errorf("Did not get expected label %s", diff.PrintWantGot(ld))
	}

	// update pod status and trigger reconcile : build is completed
	pod.Status = corev1.PodStatus{
		Phase: corev1.PodSucceeded,
	}
	if _, err := clients.Kube.CoreV1().Pods(taskRun.Namespace).UpdateStatus(testAssets.Ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Errorf("Unexpected error while updating build: %v", err)
	}

	// Before calling Reconcile again, we need to ensure that the informer's
	// lister cache is update to reflect the result of the previous Reconcile.
	testAssets.Informers.TaskRun.Informer().GetIndexer().Add(newTr)

	if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err == nil {
		t.Error("Wanted a wrapped requeue error, but got nil.")
	} else if ok, _ := controller.IsRequeueKey(err); !ok {
		t.Fatalf("Unexpected error when Reconcile(): %v", err)
	}

	newTr, err = clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Unexpected error fetching taskrun: %v", err)
	}
	if d := cmp.Diff(&apis.Condition{
		Type:    apis.ConditionSucceeded,
		Status:  corev1.ConditionTrue,
		Reason:  v1beta1.TaskRunReasonSuccessful.String(),
		Message: "All Steps have completed executing",
	}, newTr.Status.GetCondition(apis.ConditionSucceeded), ignoreLastTransitionTime); d != "" {
		t.Errorf("Did not get expected condition %s", diff.PrintWantGot(d))
	}

	wantEvents := []string{
		"Normal Started ",
		"Normal Running Not all Steps",
		"Normal Succeeded",
	}
	err = eventstest.CheckEventsOrdered(t, testAssets.Recorder.Events, "test-reconcile-pod-updateStatus", wantEvents)
	if !(err == nil) {
		t.Errorf(err.Error())
	}
}

func TestReconcileOnCompletedTaskRun(t *testing.T) {
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-success
  namespace: foo
spec:
  taskRef:
    name: test-task
status:
  conditions:
  - message: Build succeeded
    reason: Build succeeded
    status: "True"
    type: Succeeded
  startTime: "2021-12-31T23:59:45Z"
`)
	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{
			taskRun,
		},
		Tasks: []*v1beta1.Task{simpleTask},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients

	if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err != nil {
		t.Fatalf("Unexpected error when reconciling completed TaskRun : %v", err)
	}
	newTr, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Expected completed TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}
	if d := cmp.Diff(taskRun.Status.GetCondition(apis.ConditionSucceeded), newTr.Status.GetCondition(apis.ConditionSucceeded), ignoreLastTransitionTime); d != "" {
		t.Fatalf("Did not get expected condition %s", diff.PrintWantGot(d))
	}
}

func TestReconcileOnCancelledTaskRun(t *testing.T) {
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-cancelled
  namespace: foo
spec:
  status: TaskRunCancelled
  taskRef:
    name: test-task
status:
  conditions:
  - status: Unknown
    type: Succeeded
  podName: test-taskrun-run-cancelled-pod
`)
	pod, err := makePod(taskRun, simpleTask)
	if err != nil {
		t.Fatalf("MakePod: %v", err)
	}
	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{simpleTask},
		Pods:     []*corev1.Pod{pod},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients

	if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err != nil {
		t.Fatalf("Unexpected error when reconciling completed TaskRun : %v", err)
	}
	newTr, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Expected completed TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}

	expectedStatus := &apis.Condition{
		Type:    apis.ConditionSucceeded,
		Status:  corev1.ConditionFalse,
		Reason:  "TaskRunCancelled",
		Message: `TaskRun "test-taskrun-run-cancelled" was cancelled`,
	}
	if d := cmp.Diff(expectedStatus, newTr.Status.GetCondition(apis.ConditionSucceeded), ignoreLastTransitionTime); d != "" {
		t.Fatalf("Did not get expected condition %s", diff.PrintWantGot(d))
	}

	wantEvents := []string{
		"Normal Started",
		"Warning Failed TaskRun \"test-taskrun-run-cancelled\" was cancelled",
	}
	err = eventstest.CheckEventsOrdered(t, testAssets.Recorder.Events, "test-reconcile-on-cancelled-taskrun", wantEvents)
	if !(err == nil) {
		t.Errorf(err.Error())
	}

	// reconcile the completed TaskRun again without the pod as that was deleted
	d = test.Data{
		TaskRuns: []*v1beta1.TaskRun{newTr},
		Tasks:    []*v1beta1.Task{simpleTask},
	}

	testAssets, cancel = getTaskRunController(t, d)
	defer cancel()
	c = testAssets.Controller

	if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(newTr)); err != nil {
		t.Fatalf("Unexpected error when reconciling completed TaskRun : %v", err)
	}
}

func TestReconcileTimeouts(t *testing.T) {
	type testCase struct {
		name           string
		taskRun        *v1beta1.TaskRun
		expectedStatus *apis.Condition
		wantEvents     []string
	}

	testcases := []testCase{
		{
			name: "taskrun with timeout",
			taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-timeout
  namespace: foo
spec:
  taskRef:
    name: test-task
  timeout: 10s
status:
  conditions:
  - status: Unknown
    type: Succeeded
  startTime: "2021-12-31T23:59:45Z"
`),

			expectedStatus: &apis.Condition{
				Type:    apis.ConditionSucceeded,
				Status:  corev1.ConditionFalse,
				Reason:  "TaskRunTimeout",
				Message: `TaskRun "test-taskrun-timeout" failed to finish within "10s"`,
			},
			wantEvents: []string{
				"Warning Failed ",
			},
		}, {
			name: "taskrun with default timeout",
			taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-default-timeout-60-minutes
  namespace: foo
spec:
  taskRef:
    name: test-task
status:
  conditions:
  - status: Unknown
    type: Succeeded
  startTime: "2021-12-31T22:59:00Z"
`),
			expectedStatus: &apis.Condition{
				Type:    apis.ConditionSucceeded,
				Status:  corev1.ConditionFalse,
				Reason:  "TaskRunTimeout",
				Message: `TaskRun "test-taskrun-default-timeout-60-minutes" failed to finish within "1h0m0s"`,
			},
			wantEvents: []string{
				"Warning Failed ",
			},
		}, {
			name: "task run with nil timeout uses default",
			taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-nil-timeout-default-60-minutes
  namespace: foo
spec:
  taskRef:
    name: test-task
  timeout: null
status:
  conditions:
  - status: Unknown
    type: Succeeded
  startTime: "2021-12-31T22:59:00Z"
`),

			expectedStatus: &apis.Condition{
				Type:    apis.ConditionSucceeded,
				Status:  corev1.ConditionFalse,
				Reason:  "TaskRunTimeout",
				Message: `TaskRun "test-taskrun-nil-timeout-default-60-minutes" failed to finish within "1h0m0s"`,
			},
			wantEvents: []string{
				"Warning Failed ",
			},
		}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			d := test.Data{
				TaskRuns: []*v1beta1.TaskRun{tc.taskRun},
				Tasks:    []*v1beta1.Task{simpleTask},
			}
			testAssets, cancel := getTaskRunController(t, d)
			defer cancel()
			c := testAssets.Controller
			clients := testAssets.Clients

			if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tc.taskRun)); err != nil {
				t.Fatalf("Unexpected error when reconciling completed TaskRun : %v", err)
			}
			newTr, err := clients.Pipeline.TektonV1beta1().TaskRuns(tc.taskRun.Namespace).Get(testAssets.Ctx, tc.taskRun.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Expected completed TaskRun %s to exist but instead got error when getting it: %v", tc.taskRun.Name, err)
			}
			condition := newTr.Status.GetCondition(apis.ConditionSucceeded)
			if d := cmp.Diff(tc.expectedStatus, condition, ignoreLastTransitionTime); d != "" {
				t.Fatalf("Did not get expected condition %s", diff.PrintWantGot(d))
			}
			err = eventstest.CheckEventsOrdered(t, testAssets.Recorder.Events, tc.taskRun.Name, tc.wantEvents)
			if !(err == nil) {
				t.Errorf(err.Error())
			}
		})
	}
}

func TestExpandMountPath(t *testing.T) {
	expectedMountPath := "/temppath/replaced"
	expectedReplacedArgs := fmt.Sprintf("replacedArgs - %s", expectedMountPath)
	// The task's Workspace has a parameter variable
	simpleTask := parse.MustParseTask(t, `
metadata:
  name: test-task
  namespace: foo
spec:
  params:
  - name: source-path
    type: string
  - name: source-path-two
    type: string
  steps:
  - args:
    - replacedArgs - $(workspaces.tr-workspace.path)
    command:
    - echo
    image: foo
    name: simple-step
  workspaces:
  - description: a test task workspace
    mountPath: /temppath/$(params.source-path)
    name: tr-workspace
    readOnly: true
`)

	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-not-started
  namespace: foo
spec:
  params:
  - name: source-path
    value: replaced
  taskRef:
    name: test-task
  workspaces:
  - emptyDir: {}
    name: tr-workspace
`)
	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{simpleTask},
	}
	d.ConfigMaps = []*corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{Name: config.GetDefaultsConfigName(), Namespace: system.Namespace()},
			Data: map[string]string{
				"default-cloud-events-sink": "http://synk:8080",
			},
		},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	createServiceAccount(t, testAssets, "default", taskRun.Namespace)

	// Use the test assets to create a *Reconciler directly for focused testing.
	r := &Reconciler{
		KubeClientSet:     testAssets.Clients.Kube,
		PipelineClientSet: testAssets.Clients.Pipeline,
		Clock:             testClock,
		taskRunLister:     testAssets.Informers.TaskRun.Lister(),
		resourceLister:    testAssets.Informers.PipelineResource.Lister(),
		limitrangeLister:  testAssets.Informers.LimitRange.Lister(),
		cloudEventClient:  testAssets.Clients.CloudEvents,
		metrics:           nil, // Not used
		entrypointCache:   nil, // Not used
		pvcHandler:        volumeclaim.NewPVCHandler(testAssets.Clients.Kube, testAssets.Logger),
	}

	rtr := &resources.ResolvedTaskResources{
		TaskName: "test-task",
		Kind:     "Task",
		TaskSpec: &v1beta1.TaskSpec{Steps: simpleTask.Spec.Steps, Workspaces: simpleTask.Spec.Workspaces},
	}

	pod, err := r.createPod(testAssets.Ctx, taskRun, rtr)

	if err != nil {
		t.Fatalf("create pod threw error %v", err)
	}

	if vm := pod.Spec.Containers[0].VolumeMounts[0]; !strings.HasPrefix(vm.Name, "ws-9l9zj") || vm.MountPath != expectedMountPath {
		t.Fatalf("failed to find expanded Workspace mountpath %v", expectedMountPath)
	}

	if a := pod.Spec.Containers[0].Args; a[len(a)-1] != expectedReplacedArgs {
		t.Fatalf("failed to replace Workspace mountpath variable, expected %s, actual: %s", expectedReplacedArgs, a)
	}
}

func TestExpandMountPath_DuplicatePaths(t *testing.T) {
	expectedError := "workspace mount path \"/temppath/duplicate\" must be unique: workspaces[1].mountpath"
	// The task has two workspaces, with different mount path strings.
	simpleTask := parse.MustParseTask(t, `
metadata:
  name: test-task
  namespace: foo
spec:
  params:
  - name: source-path
    type: string
  - name: source-path-two
    type: string
  steps:
  - command:
    - /mycmd
    env:
    - name: foo
      value: bar
    image: foo
    name: simple-step
  workspaces:
  - description: a test task workspace
    mountPath: /temppath/$(params.source-path)
    name: tr-workspace
    readOnly: true
  - description: a second task workspace
    mountPath: /temppath/$(params.source-path-two)
    name: tr-workspace-two
    readOnly: true
`)

	// The parameter values will cause the two Workspaces to have duplicate mount path values after the parameters are expanded.
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-not-started
  namespace: foo
spec:
  params:
  - name: source-path
    value: duplicate
  - name: source-path-two
    value: duplicate
  taskRef:
    name: test-task
  workspaces:
  - emptyDir: {}
    name: tr-workspace
  - emptyDir: {}
    name: tr-workspace-two
`)
	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{simpleTask},
	}

	d.ConfigMaps = []*corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{Name: config.GetDefaultsConfigName(), Namespace: system.Namespace()},
			Data: map[string]string{
				"default-cloud-events-sink": "http://synk:8080",
			},
		},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	createServiceAccount(t, testAssets, "default", taskRun.Namespace)

	r := &Reconciler{
		KubeClientSet:     testAssets.Clients.Kube,
		PipelineClientSet: testAssets.Clients.Pipeline,
		Clock:             testClock,
		taskRunLister:     testAssets.Informers.TaskRun.Lister(),
		resourceLister:    testAssets.Informers.PipelineResource.Lister(),
		limitrangeLister:  testAssets.Informers.LimitRange.Lister(),
		cloudEventClient:  testAssets.Clients.CloudEvents,
		metrics:           nil, // Not used
		entrypointCache:   nil, // Not used
		pvcHandler:        volumeclaim.NewPVCHandler(testAssets.Clients.Kube, testAssets.Logger),
	}

	rtr := &resources.ResolvedTaskResources{
		TaskName: "test-task",
		Kind:     "Task",
		TaskSpec: &v1beta1.TaskSpec{Steps: simpleTask.Spec.Steps, Workspaces: simpleTask.Spec.Workspaces},
	}

	_, err := r.createPod(testAssets.Ctx, taskRun, rtr)

	if err == nil || err.Error() != expectedError {
		t.Errorf("Expected to fail validation for duplicate Workspace mount paths, error was %v", err)
	}
}

func TestHandlePodCreationError(t *testing.T) {
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-pod-creation-failed
spec:
  taskRef:
    name: test-task
status:
  conditions:
  - status: Unknown
    type: Succeeded
  startTime: "2022-01-01T00:00:00Z"
`)
	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{simpleTask},
	}
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()

	// Use the test assets to create a *Reconciler directly for focused testing.
	c := &Reconciler{
		KubeClientSet:     testAssets.Clients.Kube,
		PipelineClientSet: testAssets.Clients.Pipeline,
		Clock:             testClock,
		taskRunLister:     testAssets.Informers.TaskRun.Lister(),
		resourceLister:    testAssets.Informers.PipelineResource.Lister(),
		limitrangeLister:  testAssets.Informers.LimitRange.Lister(),
		cloudEventClient:  testAssets.Clients.CloudEvents,
		metrics:           nil, // Not used
		entrypointCache:   nil, // Not used
		pvcHandler:        volumeclaim.NewPVCHandler(testAssets.Clients.Kube, testAssets.Logger),
	}

	testcases := []struct {
		description    string
		err            error
		expectedType   apis.ConditionType
		expectedStatus corev1.ConditionStatus
		expectedReason string
	}{{
		description:    "exceeded quota errors are surfaced in taskrun condition but do not fail taskrun",
		err:            k8sapierrors.NewForbidden(k8sruntimeschema.GroupResource{Group: "foo", Resource: "bar"}, "baz", errors.New("exceeded quota")),
		expectedType:   apis.ConditionSucceeded,
		expectedStatus: corev1.ConditionUnknown,
		expectedReason: podconvert.ReasonExceededResourceQuota,
	}, {
		description:    "taskrun validation failed",
		err:            errors.New("TaskRun validation failed"),
		expectedType:   apis.ConditionSucceeded,
		expectedStatus: corev1.ConditionFalse,
		expectedReason: podconvert.ReasonFailedValidation,
	}, {
		description:    "errors other than exceeded quota fail the taskrun",
		err:            errors.New("this is a fatal error"),
		expectedType:   apis.ConditionSucceeded,
		expectedStatus: corev1.ConditionFalse,
		expectedReason: podconvert.ReasonCouldntGetTask,
	}}
	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			c.handlePodCreationError(testAssets.Ctx, taskRun, tc.err)
			foundCondition := false
			for _, cond := range taskRun.Status.Conditions {
				if cond.Type == tc.expectedType && cond.Status == tc.expectedStatus && cond.Reason == tc.expectedReason {
					foundCondition = true
					break
				}
			}
			if !foundCondition {
				t.Errorf("expected to find condition type %q, status %q and reason %q", tc.expectedType, tc.expectedStatus, tc.expectedReason)
			}
		})
	}
}

func TestReconcileCloudEvents(t *testing.T) {

	taskRunWithNoCEResources := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-no-ce-resources
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task
`)
	taskRunWithTwoCEResourcesNoInit := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-two-ce-resources-no-init
  namespace: foo
spec:
  resources:
    outputs:
    - name: cloud-event-resource
      resourceRef:
        name: cloud-event-resource
    - name: another-cloud-event-resource
      resourceRef:
        name: another-cloud-event-resource
  taskRef:
    name: test-two-output-task
`)
	taskRunWithTwoCEResourcesInit := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-two-ce-resources-init
  namespace: foo
spec:
  resources:
    outputs:
    - name: cloud-event-resource
      resourceRef:
        name: cloud-event-resource
    - name: another-cloud-event-resource
      resourceRef:
        name: another-cloud-event-resource
  taskRef:
    name: test-two-output-task
status:
  cloudEvents:
  - status:
      condition: Unknown
    target: https://foo
  - status:
      condition: Unknown
    target: https://bar
`)
	taskRunWithCESucceded := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-ce-succeeded
  namespace: foo
  selfLink: /task/1234
spec:
  resources:
    outputs:
    - name: cloud-event-resource
      resourceRef:
        name: cloud-event-resource
    - name: another-cloud-event-resource
      resourceRef:
        name: another-cloud-event-resource
  taskRef:
    name: test-two-output-task
status:
  cloudEvents:
  - status:
      condition: Unknown
    target: https://foo
  - status:
      condition: Unknown
    target: https://bar
  conditions:
  - status: "True"
    type: Succeeded
`)
	taskRunWithCEFailed := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-ce-failed
  namespace: foo
  selfLink: /task/1234
spec:
  resources:
    outputs:
    - name: cloud-event-resource
      resourceRef:
        name: cloud-event-resource
    - name: another-cloud-event-resource
      resourceRef:
        name: another-cloud-event-resource
  taskRef:
    name: test-two-output-task
status:
  cloudEvents:
  - status:
      condition: Unknown
    target: https://foo
  - status:
      condition: Unknown
    target: https://bar
  conditions:
  - status: "False"
    type: Succeeded
`)
	taskRunWithCESuccededOneAttempt := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-ce-succeeded-one-attempt
  namespace: foo
  selfLink: /task/1234
spec:
  resources:
    outputs:
    - name: cloud-event-resource
      resourceRef:
        name: cloud-event-resource
    - name: another-cloud-event-resource
      resourceRef:
        name: another-cloud-event-resource
  taskRef:
    name: test-two-output-task
status:
  cloudEvents:
  - status:
      condition: Unknown
      retryCount: 1
    target: https://foo
  - status:
      condition: Unknown
      message: fakemessage
    target: https://bar
  conditions:
  - status: "True"
    type: Succeeded
`)
	taskruns := []*v1beta1.TaskRun{
		taskRunWithNoCEResources, taskRunWithTwoCEResourcesNoInit,
		taskRunWithTwoCEResourcesInit, taskRunWithCESucceded, taskRunWithCEFailed,
		taskRunWithCESuccededOneAttempt,
	}

	d := test.Data{
		TaskRuns:          taskruns,
		Tasks:             []*v1beta1.Task{simpleTask, twoOutputsTask},
		ClusterTasks:      []*v1beta1.ClusterTask{},
		PipelineResources: []*resourcev1alpha1.PipelineResource{cloudEventResource, anotherCloudEventResource},
	}
	for _, tc := range []struct {
		name            string
		taskRun         *v1beta1.TaskRun
		wantCloudEvents []v1beta1.CloudEventDelivery
	}{{
		name:            "no-ce-resources",
		taskRun:         taskRunWithNoCEResources,
		wantCloudEvents: taskRunWithNoCEResources.Status.CloudEvents,
	}, {
		name:    "ce-resources-no-init",
		taskRun: taskRunWithTwoCEResourcesNoInit,
		wantCloudEvents: []v1beta1.CloudEventDelivery{
			{
				Target: cloudEventTarget1,
				Status: v1beta1.CloudEventDeliveryState{
					Condition: v1beta1.CloudEventConditionUnknown,
				},
			},
			{
				Target: cloudEventTarget2,
				Status: v1beta1.CloudEventDeliveryState{
					Condition: v1beta1.CloudEventConditionUnknown,
				},
			},
		},
	}, {
		name:    "ce-resources-init",
		taskRun: taskRunWithTwoCEResourcesInit,
		wantCloudEvents: []v1beta1.CloudEventDelivery{
			{
				Target: cloudEventTarget1,
				Status: v1beta1.CloudEventDeliveryState{
					Condition: v1beta1.CloudEventConditionUnknown,
				},
			},
			{
				Target: cloudEventTarget2,
				Status: v1beta1.CloudEventDeliveryState{
					Condition: v1beta1.CloudEventConditionUnknown,
				},
			},
		},
	}, {
		name:    "ce-resources-init-task-successful",
		taskRun: taskRunWithCESucceded,
		wantCloudEvents: []v1beta1.CloudEventDelivery{
			{
				Target: cloudEventTarget1,
				Status: v1beta1.CloudEventDeliveryState{
					Condition:  v1beta1.CloudEventConditionSent,
					RetryCount: 1,
				},
			},
			{
				Target: cloudEventTarget2,
				Status: v1beta1.CloudEventDeliveryState{
					Condition:  v1beta1.CloudEventConditionSent,
					RetryCount: 1,
				},
			},
		},
	}, {
		name:    "ce-resources-init-task-failed",
		taskRun: taskRunWithCEFailed,
		wantCloudEvents: []v1beta1.CloudEventDelivery{
			{
				Target: cloudEventTarget1,
				Status: v1beta1.CloudEventDeliveryState{
					Condition:  v1beta1.CloudEventConditionSent,
					RetryCount: 1,
				},
			},
			{
				Target: cloudEventTarget2,
				Status: v1beta1.CloudEventDeliveryState{
					Condition:  v1beta1.CloudEventConditionSent,
					RetryCount: 1,
				},
			},
		},
	}, {
		name:    "ce-resources-init-task-successful-one-attempt",
		taskRun: taskRunWithCESuccededOneAttempt,
		wantCloudEvents: []v1beta1.CloudEventDelivery{
			{
				Target: cloudEventTarget1,
				Status: v1beta1.CloudEventDeliveryState{
					Condition:  v1beta1.CloudEventConditionUnknown,
					RetryCount: 1,
				},
			},
			{
				Target: cloudEventTarget2,
				Status: v1beta1.CloudEventDeliveryState{
					Condition:  v1beta1.CloudEventConditionSent,
					RetryCount: 1,
					Error:      "fakemessage",
				},
			},
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			testAssets, cancel := getTaskRunController(t, d)
			defer cancel()
			c := testAssets.Controller
			clients := testAssets.Clients

			saName := tc.taskRun.Spec.ServiceAccountName
			if saName == "" {
				saName = "default"
			}
			if _, err := clients.Kube.CoreV1().ServiceAccounts(tc.taskRun.Namespace).Create(testAssets.Ctx, &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      saName,
					Namespace: tc.taskRun.Namespace,
				},
			}, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}

			if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tc.taskRun)); err == nil {
				// No error is ok.
			} else if ok, _ := controller.IsRequeueKey(err); !ok {
				t.Errorf("expected no error. Got error %v", err)
			}

			tr, err := clients.Pipeline.TektonV1beta1().TaskRuns(tc.taskRun.Namespace).Get(testAssets.Ctx, tc.taskRun.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("getting updated taskrun: %v", err)
			}
			opts := cloudevent.GetCloudEventDeliveryCompareOptions()
			t.Log(tr.Status.CloudEvents)
			if d := cmp.Diff(tc.wantCloudEvents, tr.Status.CloudEvents, opts...); d != "" {
				t.Errorf("Unexpected status of cloud events %s", diff.PrintWantGot(d))
			}
		})
	}
}

func TestReconcile_Single_SidecarState(t *testing.T) {
	runningState := corev1.ContainerStateRunning{StartedAt: metav1.Time{Time: now}}
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-sidecars
spec:
  taskRef:
    name: test-task-sidecar
status:
  sidecars:
  - container: sidecar-sidecar
    imageID: image-id
    name: sidecar
    running:
      startedAt: "2022-01-01T00:00:00Z"
`)

	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{taskSidecar},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	clients := testAssets.Clients

	if err := testAssets.Controller.Reconciler.Reconcile(context.Background(), getRunName(taskRun)); err != nil {
		t.Errorf("expected no error reconciling valid TaskRun but got %v", err)
	}

	getTaskRun, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Expected completed TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}

	expected := v1beta1.SidecarState{
		Name:          "sidecar",
		ImageID:       "image-id",
		ContainerName: "sidecar-sidecar",
		ContainerState: corev1.ContainerState{
			Running: &runningState,
		},
	}

	if c := cmp.Diff(expected, getTaskRun.Status.Sidecars[0]); c != "" {
		t.Errorf("TestReconcile_Single_SidecarState %s", diff.PrintWantGot(c))
	}
}

func TestReconcile_Multiple_SidecarStates(t *testing.T) {
	runningState := corev1.ContainerStateRunning{StartedAt: metav1.Time{Time: now}}
	waitingState := corev1.ContainerStateWaiting{Reason: "PodInitializing"}
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-sidecars
spec:
  taskRef:
    name: test-task-sidecar
status:
  sidecars:
  - container: sidecar-sidecar1
    imageID: image-id
    name: sidecar1
    running:
      startedAt: "2022-01-01T00:00:00Z"
  - container: sidecar-sidecar2
    imageID: image-id
    name: sidecar2
    waiting:
      reason: PodInitializing
`)

	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{taskRun},
		Tasks:    []*v1beta1.Task{taskMultipleSidecars},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	clients := testAssets.Clients

	if err := testAssets.Controller.Reconciler.Reconcile(context.Background(), getRunName(taskRun)); err != nil {
		t.Errorf("expected no error reconciling valid TaskRun but got %v", err)
	}

	getTaskRun, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Expected completed TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}

	expected := []v1beta1.SidecarState{
		{
			Name:          "sidecar1",
			ImageID:       "image-id",
			ContainerName: "sidecar-sidecar1",
			ContainerState: corev1.ContainerState{
				Running: &runningState,
			},
		},
		{
			Name:          "sidecar2",
			ImageID:       "image-id",
			ContainerName: "sidecar-sidecar2",
			ContainerState: corev1.ContainerState{
				Waiting: &waitingState,
			},
		},
	}

	for i, sc := range getTaskRun.Status.Sidecars {
		if c := cmp.Diff(expected[i], sc); c != "" {
			t.Errorf("TestReconcile_Multiple_SidecarStates sidecar%d %s", i+1, diff.PrintWantGot(c))
		}
	}
}

// TestReconcileWorkspaceMissing tests a reconcile of a TaskRun that does
// not include a Workspace that the Task is expecting.
func TestReconcileWorkspaceMissing(t *testing.T) {
	taskWithWorkspace := parse.MustParseTask(t, `
metadata:
  name: test-task-with-workspace
  namespace: foo
spec:
  workspaces:
  - description: a test task workspace
    name: ws1
    readOnly: true
`)
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-missing-workspace
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task-with-workspace
`)
	d := test.Data{
		Tasks:             []*v1beta1.Task{taskWithWorkspace},
		TaskRuns:          []*v1beta1.TaskRun{taskRun},
		ClusterTasks:      nil,
		PipelineResources: nil,
	}
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	clients := testAssets.Clients

	err := testAssets.Controller.Reconciler.Reconcile(context.Background(), getRunName(taskRun))
	if err == nil {
		t.Fatalf("expected error reconciling invalid TaskRun but got none")
	}
	if !controller.IsPermanentError(err) {
		t.Fatalf("Expected to see a permanent error when reconciling invalid TaskRun, got %s instead", err)
	}

	tr, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Expected TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}

	failedCorrectly := false
	for _, c := range tr.Status.Conditions {
		if c.Type == apis.ConditionSucceeded && c.Status == corev1.ConditionFalse && c.Reason == podconvert.ReasonFailedValidation {
			failedCorrectly = true
		}
	}
	if !failedCorrectly {
		t.Fatalf("Expected TaskRun to fail validation but it did not. Final conditions were:\n%#v", tr.Status.Conditions)
	}
}

// TestReconcileValidDefaultWorkspace tests a reconcile of a TaskRun that does
// not include a Workspace that the Task is expecting and it uses the default Workspace instead.
func TestReconcileValidDefaultWorkspace(t *testing.T) {
	taskWithWorkspace := parse.MustParseTask(t, `
metadata:
  name: test-task-with-workspace
  namespace: foo
spec:
  steps:
  - command:
    - /mycmd
    image: foo
    name: simple-step
  workspaces:
  - description: a test task workspace
    name: ws1
    readOnly: true
`)
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-default-workspace
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task-with-workspace
`)
	d := test.Data{
		Tasks:             []*v1beta1.Task{taskWithWorkspace},
		TaskRuns:          []*v1beta1.TaskRun{taskRun},
		ClusterTasks:      nil,
		PipelineResources: nil,
	}

	d.ConfigMaps = append(d.ConfigMaps, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: config.GetDefaultsConfigName(), Namespace: system.Namespace()},
		Data: map[string]string{
			"default-task-run-workspace-binding": "emptyDir: {}",
		},
	})
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	clients := testAssets.Clients

	createServiceAccount(t, testAssets, "default", "foo")

	if err := testAssets.Controller.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err == nil {
		// No error is ok.
	} else if ok, _ := controller.IsRequeueKey(err); !ok {
		t.Errorf("Expected no error reconciling valid TaskRun but got %v", err)
	}

	tr, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Expected TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}

	for _, c := range tr.Status.Conditions {
		if c.Type == apis.ConditionSucceeded && c.Status == corev1.ConditionFalse && c.Reason == podconvert.ReasonFailedValidation {
			t.Errorf("Expected TaskRun to pass Validation by using the default workspace but it did not. Final conditions were:\n%#v", tr.Status.Conditions)
		}
	}
}

// TestReconcileInvalidDefaultWorkspace tests a reconcile of a TaskRun that does
// not include a Workspace that the Task is expecting, and gets an error updating
// the TaskRun with an invalid default workspace.
func TestReconcileInvalidDefaultWorkspace(t *testing.T) {
	taskWithWorkspace := parse.MustParseTask(t, `
metadata:
  name: test-task-with-workspace
  namespace: foo
spec:
  steps:
  - command:
    - /mycmd
    image: foo
    name: simple-step
  workspaces:
  - description: a test task workspace
    name: ws1
    readOnly: true
`)
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-default-workspace
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task-with-workspace
`)
	d := test.Data{
		Tasks:             []*v1beta1.Task{taskWithWorkspace},
		TaskRuns:          []*v1beta1.TaskRun{taskRun},
		ClusterTasks:      nil,
		PipelineResources: nil,
	}

	d.ConfigMaps = append(d.ConfigMaps, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: config.GetDefaultsConfigName(), Namespace: system.Namespace()},
		Data: map[string]string{
			"default-task-run-workspace-binding": "emptyDir == {}",
		},
	})
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	clients := testAssets.Clients

	t.Logf("Creating SA %s in %s", "default", "foo")
	if _, err := clients.Kube.CoreV1().ServiceAccounts("foo").Create(testAssets.Ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "foo",
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := testAssets.Controller.Reconciler.Reconcile(context.Background(), getRunName(taskRun)); err == nil {
		t.Errorf("Expected error reconciling invalid TaskRun due to invalid workspace but got %v", err)
	}
}

// TestReconcileValidDefaultWorkspaceOmittedOptionalWorkspace tests a reconcile
// of a TaskRun that has omitted a Workspace that the Task has marked as optional
// with a Default TaskRun workspace defined. The default workspace should not be
// injected in place of the omitted optional workspace.
func TestReconcileValidDefaultWorkspaceOmittedOptionalWorkspace(t *testing.T) {
	optionalWorkspaceMountPath := "/foo/bar/baz"
	taskWithOptionalWorkspace := parse.MustParseTask(t, `
metadata:
  name: test-task-with-optional-workspace
  namespace: default
spec:
  steps:
  - command:
    - /mycmd
    image: foo
    name: simple-step
  workspaces:
  - mountPath: /foo/bar/baz
    name: optional-ws
    optional: true
`)
	taskRunOmittingWorkspace := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun
  namespace: default
spec:
  taskRef:
    name: test-task-with-optional-workspace
`)

	d := test.Data{
		Tasks:    []*v1beta1.Task{taskWithOptionalWorkspace},
		TaskRuns: []*v1beta1.TaskRun{taskRunOmittingWorkspace},
	}

	d.ConfigMaps = append(d.ConfigMaps, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: config.GetDefaultsConfigName(), Namespace: system.Namespace()},
		Data: map[string]string{
			"default-task-run-workspace-binding": "emptyDir: {}",
		},
	})
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	clients := testAssets.Clients

	createServiceAccount(t, testAssets, "default", "default")

	if err := testAssets.Controller.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRunOmittingWorkspace)); err == nil {
		t.Error("Wanted a wrapped requeue error, but got nil.")
	} else if ok, _ := controller.IsRequeueKey(err); !ok {
		t.Errorf("Unexpected reconcile error for TaskRun %q: %v", taskRunOmittingWorkspace.Name, err)
	}

	tr, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRunOmittingWorkspace.Namespace).Get(testAssets.Ctx, taskRunOmittingWorkspace.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Error getting TaskRun %q: %v", taskRunOmittingWorkspace.Name, err)
	}

	pod, err := clients.Kube.CoreV1().Pods(taskRunOmittingWorkspace.Namespace).Get(testAssets.Ctx, tr.Status.PodName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Error getting Pod for TaskRun %q: %v", taskRunOmittingWorkspace.Name, err)
	}
	for _, c := range pod.Spec.Containers {
		for _, vm := range c.VolumeMounts {
			if vm.MountPath == optionalWorkspaceMountPath {
				t.Errorf("Workspace with VolumeMount at %s should not have been found for Optional Workspace but was injected by Default TaskRun Workspace", optionalWorkspaceMountPath)
			}
		}
	}

	for _, c := range tr.Status.Conditions {
		if c.Type == apis.ConditionSucceeded && c.Status == corev1.ConditionFalse {
			t.Errorf("Unexpected unsuccessful condition for TaskRun %q:\n%#v", taskRunOmittingWorkspace.Name, tr.Status.Conditions)
		}
	}
}

func TestReconcileTaskResourceResolutionAndValidation(t *testing.T) {
	for _, tt := range []struct {
		desc             string
		d                test.Data
		wantFailedReason string
		wantEvents       []string
	}{{
		desc: "Fail ResolveTaskResources",
		d: test.Data{
			Tasks: []*v1beta1.Task{parse.MustParseTask(t, `
metadata:
  name: test-task-missing-resource
  namespace: foo
spec:
  resources:
    inputs:
    - name: workspace
      type: git
`)},
			TaskRuns: []*v1beta1.TaskRun{parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-missing-resource
  namespace: foo
spec:
  resources:
    inputs:
    - name: workspace
      resourceRef:
        name: git
  taskRef:
    apiVersion: a1
    name: test-task-missing-resource
`)},
			ClusterTasks:      nil,
			PipelineResources: nil,
		},
		wantFailedReason: podconvert.ReasonFailedResolution,
		wantEvents: []string{
			"Normal Started ",
			"Warning Failed",        // Event about the TaskRun state changed
			"Warning InternalError", // Event about the error (generated by the genreconciler)
		},
	}, {
		desc: "Fail ValidateResolvedTaskResources",
		d: test.Data{
			Tasks: []*v1beta1.Task{parse.MustParseTask(t, `
metadata:
  name: test-task-missing-resource
  namespace: foo
spec:
  resources:
    inputs:
    - name: workspace
      type: git
`)},
			TaskRuns: []*v1beta1.TaskRun{parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-missing-resource
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task-missing-resource
`)},
			ClusterTasks:      nil,
			PipelineResources: nil,
		},
		wantFailedReason: podconvert.ReasonFailedValidation,
		wantEvents: []string{
			"Normal Started ",
			"Warning Failed",        // Event about the TaskRun state changed
			"Warning InternalError", // Event about the error (generated by the genreconciler)
		},
	}, {
		desc: "Fail ValidateTaskSpecRequestResources",
		d: test.Data{
			Tasks: []*v1beta1.Task{parse.MustParseTask(t, `
metadata:
  name: test-task-invalid-taskspec-resource
  namespace: foo
spec:
  steps:
  - command:
    - cmd
    image: image
    resources:
      limits:
        cpu: "8"
        memory: 4Gi
      requests:
        cpu: "8"
        memory: 8Gi
  workspaces:
  - description: a test task workspace
    name: ws1
    readOnly: true
`)},
			TaskRuns: []*v1beta1.TaskRun{parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-invalid-taskspec-resource
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task-invalid-taskspec-resource
`)},
			ClusterTasks:      nil,
			PipelineResources: nil,
		},
		wantFailedReason: podconvert.ReasonFailedValidation,
		wantEvents: []string{
			"Normal Started ",
			"Warning Failed",        // Event about the TaskRun state changed
			"Warning InternalError", // Event about the error (generated by the genreconciler)
		},
	}} {
		t.Run(tt.desc, func(t *testing.T) {
			testAssets, cancel := getTaskRunController(t, tt.d)
			defer cancel()
			clients := testAssets.Clients
			c := testAssets.Controller

			reconcileErr := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tt.d.TaskRuns[0]))

			// When a TaskRun is invalid and can't run, we return a permanent error because
			// a regular error will tell the Reconciler to keep trying to reconcile; instead we want to stop
			// and forget about the Run.
			if reconcileErr == nil {
				t.Fatalf("Expected to see error when reconciling invalid TaskRun but none")
			}
			if !controller.IsPermanentError(reconcileErr) {
				t.Fatalf("Expected to see a permanent error when reconciling invalid TaskRun, got %s instead", reconcileErr)
			}

			tr, err := clients.Pipeline.TektonV1beta1().TaskRuns(tt.d.TaskRuns[0].Namespace).Get(testAssets.Ctx, tt.d.TaskRuns[0].Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Expected TaskRun %s to exist but instead got error when getting it: %v", tt.d.TaskRuns[0].Name, err)
			}

			for _, c := range tr.Status.Conditions {
				if c.Type != apis.ConditionSucceeded || c.Status != corev1.ConditionFalse || c.Reason != tt.wantFailedReason {
					t.Errorf("Expected TaskRun to \"%s\" but it did not. Final conditions were:\n%#v", tt.wantFailedReason, tr.Status.Conditions)
				}
			}

			err = eventstest.CheckEventsOrdered(t, testAssets.Recorder.Events, tt.desc, tt.wantEvents)
			if !(err == nil) {
				t.Errorf(err.Error())
			}
		})
	}
}

// TestReconcileWithWorkspacesIncompatibleWithAffinityAssistant tests that a TaskRun used with an associated
// Affinity Assistant is validated and that the validation fails for a TaskRun that is incompatible with
// Affinity Assistant; e.g. using more than one PVC-backed workspace.
func TestReconcileWithWorkspacesIncompatibleWithAffinityAssistant(t *testing.T) {
	taskWithTwoWorkspaces := parse.MustParseTask(t, `
metadata:
  name: test-task-two-workspaces
  namespace: foo
spec:
  workspaces:
  - description: task workspace
    name: ws1
    readOnly: true
  - description: another workspace
    name: ws2
`)
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  annotations:
    pipeline.tekton.dev/affinity-assistant: dummy-affinity-assistant
  name: taskrun-with-two-workspaces
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task-two-workspaces
  workspaces:
  - name: ws1
    persistentVolumeClaim:
      claimName: pvc1
  - name: ws2
    volumeClaimTemplate:
      metadata:
        name: pvc2
`)

	d := test.Data{
		Tasks:             []*v1beta1.Task{taskWithTwoWorkspaces},
		TaskRuns:          []*v1beta1.TaskRun{taskRun},
		ClusterTasks:      nil,
		PipelineResources: nil,
	}
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	clients := testAssets.Clients
	createServiceAccount(t, testAssets, "default", "foo")
	_ = testAssets.Controller.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun))

	_, err := clients.Pipeline.TektonV1beta1().Tasks(taskRun.Namespace).Get(testAssets.Ctx, taskWithTwoWorkspaces.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("krux: %v", err)
	}

	ttt, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}

	if len(ttt.Status.Conditions) != 1 {
		t.Errorf("unexpected number of Conditions, expected 1 Condition")
	}

	for _, cond := range ttt.Status.Conditions {
		if cond.Reason != podconvert.ReasonFailedValidation {
			t.Errorf("unexpected Reason on the Condition, expected: %s, got: %s", podconvert.ReasonFailedValidation, cond.Reason)
		}
	}
}

// TestReconcileWorkspaceWithVolumeClaimTemplate tests a reconcile of a TaskRun that has
// a Workspace with VolumeClaimTemplate and check that it is translated to a created PersistentVolumeClaim.
func TestReconcileWorkspaceWithVolumeClaimTemplate(t *testing.T) {
	taskWithWorkspace := parse.MustParseTask(t, `
metadata:
  name: test-task-with-workspace
  namespace: foo
spec:
  steps:
  - command:
    - /mycmd
    image: foo
    name: simple-step
  workspaces:
  - description: a test task workspace
    name: ws1
    readOnly: true
`)
	taskRun := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-missing-workspace
  namespace: foo
spec:
  taskRef:
    apiVersion: a1
    name: test-task-with-workspace
  workspaces:
  - name: ws1
    volumeClaimTemplate:
      metadata:
        creationTimestamp: null
        name: mypvc
`)
	d := test.Data{
		Tasks:             []*v1beta1.Task{taskWithWorkspace},
		TaskRuns:          []*v1beta1.TaskRun{taskRun},
		ClusterTasks:      nil,
		PipelineResources: nil,
	}
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	clients := testAssets.Clients
	createServiceAccount(t, testAssets, "default", "foo")

	if err := testAssets.Controller.Reconciler.Reconcile(testAssets.Ctx, getRunName(taskRun)); err == nil {
		t.Error("Wanted a wrapped requeue error, but got nil.")
	} else if ok, _ := controller.IsRequeueKey(err); !ok {
		t.Errorf("expected no error reconciling valid TaskRun but got %v", err)
	}

	ttt, err := clients.Pipeline.TektonV1beta1().TaskRuns(taskRun.Namespace).Get(testAssets.Ctx, taskRun.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected TaskRun %s to exist but instead got error when getting it: %v", taskRun.Name, err)
	}

	for _, w := range ttt.Spec.Workspaces {
		if w.PersistentVolumeClaim != nil {
			t.Fatalf("expected workspace from volumeClaimTemplate to be translated to PVC")
		}
		expectedPVCName := volumeclaim.GetPersistentVolumeClaimName(&corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name: w.VolumeClaimTemplate.Name,
			},
		}, w, *kmeta.NewControllerRef(ttt))
		_, err = clients.Kube.CoreV1().PersistentVolumeClaims(taskRun.Namespace).Get(testAssets.Ctx, expectedPVCName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected PVC %s to exist but instead got error when getting it: %v", expectedPVCName, err)
		}
	}
}

func TestFailTaskRun(t *testing.T) {
	testCases := []struct {
		name               string
		taskRun            *v1beta1.TaskRun
		pod                *corev1.Pod
		reason             v1beta1.TaskRunReason
		message            string
		expectedStatus     apis.Condition
		expectedStepStates []v1beta1.StepState
	}{{
		name: "no-pod-scheduled",
		taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-failed
  namespace: foo
spec:
  status: TaskRunCancelled
  taskRef:
    name: test-task
status:
  conditions:
  - status: Unknown
    type: Succeeded
`),
		reason:  "some reason",
		message: "some message",
		expectedStatus: apis.Condition{
			Type:    apis.ConditionSucceeded,
			Status:  corev1.ConditionFalse,
			Reason:  "some reason",
			Message: "some message",
		},
	}, {
		name: "pod-scheduled",
		taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-failed
  namespace: foo
spec:
  status: TaskRunCancelled
  taskRef:
    name: test-task
status:
  conditions:
  - status: Unknown
    type: Succeeded
  podName: foo-is-bar
`),
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "foo",
			Name:      "foo-is-bar",
		}},
		reason:  "some reason",
		message: "some message",
		expectedStatus: apis.Condition{
			Type:    apis.ConditionSucceeded,
			Status:  corev1.ConditionFalse,
			Reason:  "some reason",
			Message: "some message",
		},
	}, {
		name: "step-status-update-cancel",
		taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-cancel
  namespace: foo
spec:
  status: TaskRunCancelled
  taskRef:
    name: test-task
status:
  conditions:
  - status: Unknown
    type: Succeeded
  podName: foo-is-bar
  steps:
  - running:
      startedAt: "2022-01-01T00:00:00Z"
`),
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "foo",
			Name:      "foo-is-bar",
		}},
		reason:  v1beta1.TaskRunReasonCancelled,
		message: "TaskRun test-taskrun-run-cancel was cancelled",
		expectedStatus: apis.Condition{
			Type:    apis.ConditionSucceeded,
			Status:  corev1.ConditionFalse,
			Reason:  v1beta1.TaskRunReasonCancelled.String(),
			Message: "TaskRun test-taskrun-run-cancel was cancelled",
		},
		expectedStepStates: []v1beta1.StepState{
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Reason:   v1beta1.TaskRunReasonCancelled.String(),
					},
				},
			},
		},
	}, {
		name: "step-status-update-timeout",
		taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-timeout
  namespace: foo
spec:
  taskRef:
    name: test-task
  timeout: 10s
status:
  conditions:
  - status: Unknown
    type: Succeeded
  podName: foo-is-bar
  steps:
  - running:
      startedAt: "2022-01-01T00:00:00Z"
`),
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "foo",
			Name:      "foo-is-bar",
		}},
		reason:  v1beta1.TaskRunReasonTimedOut,
		message: "TaskRun test-taskrun-run-timeout failed to finish within 10s",
		expectedStatus: apis.Condition{
			Type:    apis.ConditionSucceeded,
			Status:  corev1.ConditionFalse,
			Reason:  v1beta1.TaskRunReasonTimedOut.String(),
			Message: "TaskRun test-taskrun-run-timeout failed to finish within 10s",
		},
		expectedStepStates: []v1beta1.StepState{
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Reason:   v1beta1.TaskRunReasonTimedOut.String(),
					},
				},
			},
		},
	}, {
		name: "step-status-update-multiple-steps",
		taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-timeout-multiple-steps
  namespace: foo
spec:
  taskRef:
    name: test-task-multi-steps
  timeout: 10s
status:
  conditions:
  - status: Unknown
    type: Succeeded
  podName: foo-is-bar
  steps:
  - terminated:
      exitCode: 0
      finishedAt: "2022-01-01T00:00:00Z"
      reason: Completed
      startedAt: "2022-01-01T00:00:00Z"
  - running:
      startedAt: "2022-01-01T00:00:00Z"
  - running:
      startedAt: "2022-01-01T00:00:00Z"
`),
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "foo",
			Name:      "foo-is-bar",
		}},
		reason:  v1beta1.TaskRunReasonTimedOut,
		message: "TaskRun test-taskrun-run-timeout-multiple-steps failed to finish within 10s",
		expectedStatus: apis.Condition{
			Type:    apis.ConditionSucceeded,
			Status:  corev1.ConditionFalse,
			Reason:  v1beta1.TaskRunReasonTimedOut.String(),
			Message: "TaskRun test-taskrun-run-timeout-multiple-steps failed to finish within 10s",
		},
		expectedStepStates: []v1beta1.StepState{
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 0,
						Reason:   "Completed",
					},
				},
			},
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Reason:   v1beta1.TaskRunReasonTimedOut.String(),
					},
				},
			},
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Reason:   v1beta1.TaskRunReasonTimedOut.String(),
					},
				},
			},
		},
	}, {
		name: "step-status-update-multiple-steps-waiting-state",
		taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-timeout-multiple-steps-waiting
  namespace: foo
spec:
  taskRef:
    name: test-task-multi-steps
  timeout: 10s
status:
  conditions:
  - status: Unknown
    type: Succeeded
  podName: foo-is-bar
  steps:
  - waiting:
      reason: PodInitializing
  - waiting:
      reason: PodInitializing
  - waiting:
      reason: PodInitializing
`),
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "foo",
			Name:      "foo-is-bar",
		}},
		reason:  v1beta1.TaskRunReasonTimedOut,
		message: "TaskRun test-taskrun-run-timeout-multiple-steps-waiting failed to finish within 10s",
		expectedStatus: apis.Condition{
			Type:    apis.ConditionSucceeded,
			Status:  corev1.ConditionFalse,
			Reason:  v1beta1.TaskRunReasonTimedOut.String(),
			Message: "TaskRun test-taskrun-run-timeout-multiple-steps-waiting failed to finish within 10s",
		},
		expectedStepStates: []v1beta1.StepState{
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Reason:   v1beta1.TaskRunReasonTimedOut.String(),
					},
				},
			},
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Reason:   v1beta1.TaskRunReasonTimedOut.String(),
					},
				},
			},
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Reason:   v1beta1.TaskRunReasonTimedOut.String(),
					},
				},
			},
		},
	}, {
		name: "step-status-update-with-multiple-steps-and-some-continue-on-error",
		taskRun: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun-run-ignore-step-error
  namespace: foo
spec:
  taskRef:
    name: test-task-multi-steps-with-ignore-error
status:
  conditions:
  - status: "True"
    type: Succeeded
  podName: foo-is-bar
  steps:
  - terminated:
      exitCode: 12
      finishedAt: "2022-01-01T00:00:00Z"
      reason: Completed
      startedAt: "2022-01-01T00:00:00Z"
  - running:
      startedAt: "2022-01-01T00:00:00Z"
`),
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "foo",
			Name:      "foo-is-bar",
		}},
		reason:  v1beta1.TaskRunReasonTimedOut,
		message: "TaskRun test-taskrun-run-timeout-multiple-steps failed to finish within 10s",
		expectedStatus: apis.Condition{
			Type:    apis.ConditionSucceeded,
			Status:  corev1.ConditionFalse,
			Reason:  v1beta1.TaskRunReasonTimedOut.String(),
			Message: "TaskRun test-taskrun-run-timeout-multiple-steps failed to finish within 10s",
		},
		expectedStepStates: []v1beta1.StepState{
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 12,
						Reason:   "Completed",
					},
				},
			},
			{
				ContainerState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Reason:   v1beta1.TaskRunReasonTimedOut.String(),
					},
				},
			},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := test.Data{
				TaskRuns: []*v1beta1.TaskRun{tc.taskRun},
			}
			if tc.pod != nil {
				d.Pods = []*corev1.Pod{tc.pod}
			}

			testAssets, cancel := getTaskRunController(t, d)
			defer cancel()

			// Use the test assets to create a *Reconciler directly for focused testing.
			c := &Reconciler{
				KubeClientSet:     testAssets.Clients.Kube,
				PipelineClientSet: testAssets.Clients.Pipeline,
				Clock:             testClock,
				taskRunLister:     testAssets.Informers.TaskRun.Lister(),
				resourceLister:    testAssets.Informers.PipelineResource.Lister(),
				limitrangeLister:  testAssets.Informers.LimitRange.Lister(),
				cloudEventClient:  testAssets.Clients.CloudEvents,
				metrics:           nil, // Not used
				entrypointCache:   nil, // Not used
				pvcHandler:        volumeclaim.NewPVCHandler(testAssets.Clients.Kube, testAssets.Logger),
			}

			err := c.failTaskRun(testAssets.Ctx, tc.taskRun, tc.reason, tc.message)
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tc.taskRun.Status.GetCondition(apis.ConditionSucceeded), &tc.expectedStatus, ignoreLastTransitionTime); d != "" {
				t.Fatalf(diff.PrintWantGot(d))
			}

			if tc.expectedStepStates != nil {
				ignoreTerminatedFields := cmpopts.IgnoreFields(corev1.ContainerStateTerminated{}, "StartedAt", "FinishedAt")
				if c := cmp.Diff(tc.expectedStepStates, tc.taskRun.Status.Steps, ignoreTerminatedFields); c != "" {
					t.Errorf("test %s failed: %s", tc.name, diff.PrintWantGot(c))
				}
			}
		})
	}
}

func Test_storeTaskSpec(t *testing.T) {
	tr := parse.MustParseTaskRun(t, `
metadata:
  annotations:
    io.annotation: value
  labels:
    lbl1: value1
  name: foo
spec:
  taskRef:
    name: foo-task
`)

	ts := v1beta1.TaskSpec{
		Description: "foo-task",
	}
	ts1 := v1beta1.TaskSpec{
		Description: "bar-task",
	}
	want := tr.DeepCopy()
	want.Status = v1beta1.TaskRunStatus{
		TaskRunStatusFields: v1beta1.TaskRunStatusFields{
			TaskSpec: ts.DeepCopy(),
		},
	}
	want.ObjectMeta.Labels["tekton.dev/task"] = tr.ObjectMeta.Name

	// The first time we set it, it should get copied.
	if err := storeTaskSpecAndMergeMeta(tr, &ts, &tr.ObjectMeta); err != nil {
		t.Errorf("storeTaskSpec() error = %v", err)
	}
	if d := cmp.Diff(tr, want); d != "" {
		t.Fatalf(diff.PrintWantGot(d))
	}

	// The next time, it should not get overwritten
	if err := storeTaskSpecAndMergeMeta(tr, &ts1, &metav1.ObjectMeta{}); err != nil {
		t.Errorf("storeTaskSpec() error = %v", err)
	}
	if d := cmp.Diff(tr, want); d != "" {
		t.Fatalf(diff.PrintWantGot(d))
	}
}

func Test_storeTaskSpec_metadata(t *testing.T) {
	taskrunlabels := map[string]string{"lbl1": "value1", "lbl2": "value2"}
	taskrunannotations := map[string]string{"io.annotation.1": "value1", "io.annotation.2": "value2"}
	tasklabels := map[string]string{"lbl1": "another value", "lbl3": "value3"}
	taskannotations := map[string]string{"io.annotation.1": "another value", "io.annotation.3": "value3"}
	wantedlabels := map[string]string{"lbl1": "value1", "lbl2": "value2", "lbl3": "value3"}
	wantedannotations := map[string]string{"io.annotation.1": "value1", "io.annotation.2": "value2", "io.annotation.3": "value3"}

	tr := &v1beta1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: taskrunlabels, Annotations: taskrunannotations},
	}
	meta := metav1.ObjectMeta{Labels: tasklabels, Annotations: taskannotations}
	if err := storeTaskSpecAndMergeMeta(tr, &v1beta1.TaskSpec{}, &meta); err != nil {
		t.Errorf("storeTaskSpecAndMergeMeta error = %v", err)
	}
	if d := cmp.Diff(tr.ObjectMeta.Labels, wantedlabels); d != "" {
		t.Fatalf(diff.PrintWantGot(d))
	}
	if d := cmp.Diff(tr.ObjectMeta.Annotations, wantedannotations); d != "" {
		t.Fatalf(diff.PrintWantGot(d))
	}
}

func TestWillOverwritePodAffinity(t *testing.T) {
	affinity := &corev1.Affinity{
		PodAffinity: &corev1.PodAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					Namespaces: []string{"tekton-pipelines"},
				},
			},
		},
	}
	affinityAssistantName := "pipeline.tekton.dev/affinity-assistant"

	tcs := []struct {
		name                string
		hasTemplateAffinity bool
		annotations         map[string]string
		expected            bool
	}{
		{
			name:     "no settings",
			expected: false,
		},
		{
			name: "no PodTemplate affinity set",
			annotations: map[string]string{
				affinityAssistantName: "affinity-assistant",
			},
			expected: false,
		},
		{
			name:                "affinity assistant not set",
			hasTemplateAffinity: true,
			expected:            false,
		},
		{
			name:                "PodTemplate affinity will be overwritten with affinity assistant",
			hasTemplateAffinity: true,
			annotations: map[string]string{
				affinityAssistantName: "affinity-assistant",
			},
			expected: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tr := &v1beta1.TaskRun{
				Spec: v1beta1.TaskRunSpec{
					PodTemplate: &pod.Template{},
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: tc.annotations,
				},
			}
			if tc.hasTemplateAffinity {
				tr.Spec.PodTemplate.Affinity = affinity
			}

			if got := willOverwritePodSetAffinity(tr); got != tc.expected {
				t.Errorf("expected: %t got: %t", tc.expected, got)
			}
		})
	}
}

func TestPodAdoption(t *testing.T) {
	tr := parse.MustParseTaskRun(t, `
metadata:
  labels:
    mylabel: myvalue
  name: test-taskrun
  namespace: foo
spec:
  taskSpec:
    steps:
    - command:
      - /mycmd
      image: myimage
      name: mycontainer
`)

	d := test.Data{
		TaskRuns: []*v1beta1.TaskRun{tr},
	}
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients
	createServiceAccount(t, testAssets, "default", tr.Namespace)

	// Reconcile the TaskRun.  This creates a Pod.
	if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tr)); err == nil {
		t.Error("Wanted a wrapped requeue error, but got nil.")
	} else if ok, _ := controller.IsRequeueKey(err); !ok {
		t.Errorf("Error reconciling TaskRun. Got error %v", err)
	}

	// Get the updated TaskRun.
	reconciledRun, err := clients.Pipeline.TektonV1beta1().TaskRuns(tr.Namespace).Get(testAssets.Ctx, tr.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Error getting updated TaskRun: %v", err)
	}

	// Save the name of the Pod that was created.
	podName := reconciledRun.Status.PodName
	if podName == "" {
		t.Fatal("Expected a pod to be created but the pod name is not set in the TaskRun")
	}

	// Add a label to the TaskRun.  This tests a scenario in issue 3656 which could prevent the reconciler
	// from finding a Pod when the pod name is missing from the status.
	reconciledRun.ObjectMeta.Labels["bah"] = "humbug"
	reconciledRun, err = clients.Pipeline.TektonV1beta1().TaskRuns(tr.Namespace).Update(testAssets.Ctx, reconciledRun, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Unexpected error when updating status: %v", err)
	}

	// The label update triggers another reconcile.  Depending on timing, the TaskRun passed to the reconcile may or may not
	// have the updated status with the name of the created pod.  Clear the status because we want to test the case where the
	// status does not have the pod name.
	reconciledRun.Status = v1beta1.TaskRunStatus{}
	if _, err := clients.Pipeline.TektonV1beta1().TaskRuns("foo").UpdateStatus(testAssets.Ctx, reconciledRun, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Unexpected error when updating status: %v", err)
	}

	// Reconcile the TaskRun again.
	if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tr)); err == nil {
		t.Error("Wanted a wrapped requeue error, but got nil.")
	} else if ok, _ := controller.IsRequeueKey(err); !ok {
		t.Errorf("Error reconciling TaskRun again. Got error %v", err)
	}

	// Get the updated TaskRun.
	reconciledRun, err = clients.Pipeline.TektonV1beta1().TaskRuns(tr.Namespace).Get(testAssets.Ctx, tr.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Error getting updated TaskRun after second reconcile: %v", err)
	}

	// Verify that the reconciler found the existing pod instead of creating a new one.
	if reconciledRun.Status.PodName != podName {
		t.Fatalf("First reconcile created pod %s but TaskRun now has another pod name %s", podName, reconciledRun.Status.PodName)
	}

}

func TestStopSidecars_ClientGetPodForTaskSpecWithSidecars(t *testing.T) {
	tr := parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun
  namespace: foo
status:
  conditions:
  - status: "True"
    type: Succeeded
  podName: test-taskrun-pod
  sidecars:
  - running:
      startedAt: "2000-01-01T01:01:01Z"
  startTime: "2000-01-01T01:01:01Z"
`)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-taskrun-pod",
			Namespace: "foo",
		},
	}

	d := test.Data{
		Pods:     []*corev1.Pod{pod},
		TaskRuns: []*v1beta1.TaskRun{tr},
	}

	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients
	reconcileErr := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tr))

	// We do not expect an error
	if reconcileErr != nil {
		t.Errorf("Expected no error to be returned by reconciler: %v", reconcileErr)
	}

	// Verify that the pod was retrieved.
	getPodFound := false
	for _, action := range clients.Kube.Actions() {
		if action.Matches("get", "pods") {
			getPodFound = true
			break
		}
	}
	if !getPodFound {
		t.Errorf("expected the pod to be retrieved to check if sidecars need to be stopped")
	}
}

func TestStopSidecars_NoClientGetPodForTaskSpecWithoutRunningSidecars(t *testing.T) {
	for _, tc := range []struct {
		desc string
		tr   *v1beta1.TaskRun
	}{{
		desc: "no sidecars",
		tr: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun
  namespace: foo
status:
  conditions:
  - status: "True"
    type: Succeeded
  podName: test-taskrun-pod
  startTime: "2000-01-01T01:01:01Z"
`),
	}, {
		desc: "sidecars are terminated",
		tr: parse.MustParseTaskRun(t, `
metadata:
  name: test-taskrun
  namespace: foo
status:
  conditions:
  - status: "True"
    type: Succeeded
  podName: test-taskrun-pod
  sidecars:
  - terminated:
      exitCode: 0
      finishedAt: "2000-01-01T01:01:01Z"
      startedAt: "2000-01-01T01:01:01Z"
  startTime: "2000-01-01T01:01:01Z"
`),
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			d := test.Data{
				TaskRuns: []*v1beta1.TaskRun{tc.tr},
			}

			testAssets, cancel := getTaskRunController(t, d)
			defer cancel()
			c := testAssets.Controller
			clients := testAssets.Clients
			reconcileErr := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tc.tr))

			// We do not expect an error
			if reconcileErr != nil {
				t.Errorf("Expected no error to be returned by reconciler: %v", reconcileErr)
			}

			// Verify that the pod was not retrieved
			for _, action := range clients.Kube.Actions() {
				if action.Matches("get", "pods") {
					t.Errorf("expected the pod not to be retrieved because the TaskRun has no sidecars")
				}
			}
		})
	}
}

func TestReconcileOnTaskRunSign(t *testing.T) {
	sc := &spire.MockClient{}

	taskSt := &apis.Condition{
		Type:    apis.ConditionSucceeded,
		Status:  corev1.ConditionTrue,
		Reason:  "Build succeeded",
		Message: "Build succeeded",
	}
	taskRunStartedUnsigned := &v1beta1.TaskRun{
		ObjectMeta: objectMeta("taskrun-started-unsigned", "foo"),
		Spec: v1beta1.TaskRunSpec{
			TaskRef: &v1beta1.TaskRef{
				Name: simpleTask.Name,
			},
		},
		Status: v1beta1.TaskRunStatus{
			Status: duckv1beta1.Status{
				Conditions: duckv1beta1.Conditions{
					*taskSt,
				},
			},
			TaskRunStatusFields: v1beta1.TaskRunStatusFields{
				StartTime: &metav1.Time{Time: now.Add(-15 * time.Second)},
			},
		},
	}
	taskRunUnstarted := &v1beta1.TaskRun{
		ObjectMeta: objectMeta("taskrun-unstarted", "foo"),
		Spec: v1beta1.TaskRunSpec{
			TaskRef: &v1beta1.TaskRef{
				Name: simpleTask.Name,
			},
		},
		Status: v1beta1.TaskRunStatus{
			Status: duckv1beta1.Status{
				Conditions: duckv1beta1.Conditions{
					*taskSt,
				},
			},
		},
	}
	taskRunStartedSigned := &v1beta1.TaskRun{
		ObjectMeta: objectMeta("taskrun-started-signed", "foo"),
		Spec: v1beta1.TaskRunSpec{
			TaskRef: &v1beta1.TaskRef{
				Name: simpleTask.Name,
			},
		},
		Status: v1beta1.TaskRunStatus{
			Status: duckv1beta1.Status{
				Conditions: duckv1beta1.Conditions{
					*taskSt,
				},
			},
		},
	}
	if err := sc.AppendStatusInternalAnnotation(context.Background(), taskRunStartedSigned); err != nil {
		t.Fatal("failed to sign test taskrun")
	}

	d := test.Data{
		ConfigMaps: []*corev1.ConfigMap{{
			ObjectMeta: metav1.ObjectMeta{Name: config.GetFeatureFlagsConfigName(), Namespace: system.Namespace()},
			Data: map[string]string{
				"enable-spire": "true",
			},
		}},

		TaskRuns: []*v1beta1.TaskRun{
			taskRunStartedUnsigned, taskRunUnstarted, taskRunStartedSigned,
		},
		Tasks: []*v1beta1.Task{simpleTask},
	}
	testAssets, cancel := getTaskRunController(t, d)
	defer cancel()
	c := testAssets.Controller
	clients := testAssets.Clients

	testCases := []struct {
		name       string
		tr         *v1beta1.TaskRun
		verifiable bool
	}{
		{
			name:       "sign/verify unstarted taskrun",
			tr:         taskRunUnstarted,
			verifiable: true,
		},
		{
			name:       "sign/verify signed started taskrun",
			tr:         taskRunStartedSigned,
			verifiable: true,
		},
		{
			name:       "sign/verify unsigned started taskrun should fail",
			tr:         taskRunStartedUnsigned,
			verifiable: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Reconciler.Reconcile(testAssets.Ctx, getRunName(tc.tr)); err != nil {
				t.Fatalf("Unexpected error when reconciling completed TaskRun : %v", err)
			}
			newTr, err := clients.Pipeline.TektonV1beta1().TaskRuns(tc.tr.Namespace).Get(testAssets.Ctx, tc.tr.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Expected completed TaskRun %s to exist but instead got error when getting it: %v", tc.tr.Name, err)
			}
			verified := sc.CheckSpireVerifiedFlag(newTr)
			if verified != tc.verifiable {
				t.Fatalf("expected verifiable: %v, got %v", tc.verifiable, verified)
			}
		})
	}
}

func Test_validateTaskSpecRequestResources_ValidResources(t *testing.T) {
	ctx := context.Background()

	tcs := []struct {
		name     string
		taskSpec *v1beta1.TaskSpec
	}{{
		name: "no requested resources",
		taskSpec: &v1beta1.TaskSpec{
			Steps: []v1beta1.Step{
				{
					Container: corev1.Container{
						Image:   "image",
						Command: []string{"cmd"},
					},
				}},
			StepTemplate: &corev1.Container{
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("4"),
						corev1.ResourceMemory: resource.MustParse("8Gi"),
					},
				},
			},
		},
	}, {
		name: "no limit configured",
		taskSpec: &v1beta1.TaskSpec{
			Steps: []v1beta1.Step{{Container: corev1.Container{
				Image:   "image",
				Command: []string{"cmd"},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("4Gi"),
					},
				},
			}}},
		},
	}, {
		name: "request less or equal than step limit but larger than steptemplate limit",
		taskSpec: &v1beta1.TaskSpec{
			Steps: []v1beta1.Step{{Container: corev1.Container{
				Image:   "image",
				Command: []string{"cmd"},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("4Gi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("8Gi"),
					},
				},
			}}},
			StepTemplate: &corev1.Container{
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("4"),
						corev1.ResourceMemory: resource.MustParse("4Gi"),
					},
				},
			},
		},
	}, {
		name: "request less or equal than step limit",
		taskSpec: &v1beta1.TaskSpec{
			Steps: []v1beta1.Step{{Container: corev1.Container{
				Image:   "image",
				Command: []string{"cmd"},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("4Gi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("8Gi"),
					},
				},
			}}},
		},
	}, {
		name: "request less or equal than steptemplate limit",
		taskSpec: &v1beta1.TaskSpec{
			Steps: []v1beta1.Step{{Container: corev1.Container{
				Image:   "image",
				Command: []string{"cmd"},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("4Gi"),
					},
				},
			}}},
			StepTemplate: &corev1.Container{
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("8Gi"),
					},
				},
			},
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTaskSpecRequestResources(ctx, tc.taskSpec); err != nil {
				t.Fatalf("Expected to see error when validating invalid TaskSpec resources but saw none")
			}
		})
	}

}

func Test_validateTaskSpecRequestResources_InvalidResources(t *testing.T) {
	ctx := context.Background()
	tcs := []struct {
		name     string
		taskSpec *v1beta1.TaskSpec
	}{{
		name: "step request larger than step limit",
		taskSpec: &v1beta1.TaskSpec{
			Steps: []v1beta1.Step{{Container: corev1.Container{
				Image:   "image",
				Command: []string{"cmd"},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("8Gi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("4Gi"),
					},
				},
			}}}},
	}, {
		name: "step request larger than steptemplate limit",
		taskSpec: &v1beta1.TaskSpec{
			Steps: []v1beta1.Step{{Container: corev1.Container{
				Image:   "image",
				Command: []string{"cmd"},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("8Gi"),
					},
				},
			}}},
			StepTemplate: &corev1.Container{
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("8"),
						corev1.ResourceMemory: resource.MustParse("4Gi"),
					},
				},
			},
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTaskSpecRequestResources(ctx, tc.taskSpec); err == nil {
				t.Fatalf("Expected to see error when validating invalid TaskSpec resources but saw none")
			}
		})
	}
}

func podVolumeMounts(idx, totalSteps int) []corev1.VolumeMount {
	var mnts []corev1.VolumeMount
	mnts = append(mnts, corev1.VolumeMount{
		Name:      "tekton-internal-bin",
		MountPath: "/tekton/bin",
		ReadOnly:  true,
	})
	for i := 0; i < totalSteps; i++ {
		mnts = append(mnts, corev1.VolumeMount{
			Name:      fmt.Sprintf("tekton-internal-run-%d", i),
			MountPath: filepath.Join("/tekton/run", strconv.Itoa(i)),
			ReadOnly:  i != idx,
		})
	}
	if idx == 0 {
		mnts = append(mnts, corev1.VolumeMount{
			Name:      "tekton-internal-downward",
			MountPath: "/tekton/downward",
			ReadOnly:  true,
		})
	}
	mnts = append(mnts, corev1.VolumeMount{
		Name:      fmt.Sprintf("tekton-creds-init-home-%d", idx),
		MountPath: "/tekton/creds",
	})
	mnts = append(mnts, corev1.VolumeMount{
		Name:      "tekton-internal-workspace",
		MountPath: workspaceDir,
	})
	mnts = append(mnts, corev1.VolumeMount{
		Name:      "tekton-internal-home",
		MountPath: "/tekton/home",
	})
	mnts = append(mnts, corev1.VolumeMount{
		Name:      "tekton-internal-results",
		MountPath: "/tekton/results",
	})
	mnts = append(mnts, corev1.VolumeMount{
		Name:      "tekton-internal-steps",
		MountPath: "/tekton/steps",
		ReadOnly:  true,
	})

	return mnts
}

func podArgs(stepName string, cmd string, additionalArgs []string, idx int) []string {
	args := []string{
		"-wait_file",
	}
	if idx == 0 {
		args = append(args, "/tekton/downward/ready", "-wait_file_content")
	} else {
		args = append(args, fmt.Sprintf("/tekton/run/%d/out", idx-1))
	}
	args = append(args,
		"-post_file",
		fmt.Sprintf("/tekton/run/%d/out", idx),
		"-termination_path",
		"/tekton/termination",
		"-step_metadata_dir",
		fmt.Sprintf("/tekton/run/%d/status", idx),
		"-entrypoint",
		cmd,
		"--",
	)

	args = append(args, additionalArgs...)

	return args
}

func podObjectMeta(name, taskName, taskRunName, ns string, isClusterTask bool) metav1.ObjectMeta {
	trueB := true
	om := metav1.ObjectMeta{
		Name:      name,
		Namespace: ns,
		Annotations: map[string]string{
			podconvert.ReleaseAnnotation: fakeVersion,
		},
		Labels: map[string]string{
			pipeline.TaskRunLabelKey:       taskRunName,
			"app.kubernetes.io/managed-by": "tekton-pipelines",
		},
		OwnerReferences: []metav1.OwnerReference{{
			Kind:               "TaskRun",
			Name:               taskRunName,
			Controller:         &trueB,
			BlockOwnerDeletion: &trueB,
			APIVersion:         currentAPIVersion,
		}},
	}

	if taskName != "" {
		if isClusterTask {
			om.Labels[pipeline.ClusterTaskLabelKey] = taskName
		} else {
			om.Labels[pipeline.TaskLabelKey] = taskName
		}
	}

	return om
}

type stepForExpectedPod struct {
	name            string
	image           string
	cmd             string
	args            []string
	envVars         map[string]string
	workingDir      string
	securityContext *corev1.SecurityContext
}

func expectedPod(podName, taskName, taskRunName, ns, saName string, isClusterTask bool, extraVolumes []corev1.Volume, steps []stepForExpectedPod) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: podObjectMeta(podName, taskName, taskRunName, ns, isClusterTask),
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				workspaceVolume,
				homeVolume,
				resultsVolume,
				stepsVolume,
				binVolume,
				downwardVolume,
			},
			InitContainers:        []corev1.Container{placeToolsInitContainer},
			RestartPolicy:         corev1.RestartPolicyNever,
			ActiveDeadlineSeconds: &defaultActiveDeadlineSeconds,
			ServiceAccountName:    saName,
		},
	}

	stepNames := make([]string, 0, len(steps))
	for _, s := range steps {
		stepNames = append(stepNames, fmt.Sprintf("step-%s", s.name))
	}
	p.Spec.InitContainers = []corev1.Container{placeToolsInitContainer, {
		Name:         "step-init",
		Image:        images.EntrypointImage,
		Command:      append([]string{"/ko-app/entrypoint", "step-init"}, stepNames...),
		WorkingDir:   "/",
		VolumeMounts: []v1.VolumeMount{{Name: "tekton-internal-steps", MountPath: "/tekton/steps"}},
	}}

	for idx, s := range steps {
		p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{
			Name:         fmt.Sprintf("tekton-creds-init-home-%d", idx),
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}},
		})
		p.Spec.Volumes = append(p.Spec.Volumes, runVolume(idx))

		stepContainer := corev1.Container{
			Image:                  s.image,
			Name:                   fmt.Sprintf("step-%s", s.name),
			Command:                []string{entrypointLocation},
			VolumeMounts:           podVolumeMounts(idx, len(steps)),
			TerminationMessagePath: "/tekton/termination",
		}
		stepContainer.Args = podArgs(s.name, s.cmd, s.args, idx)

		for k, v := range s.envVars {
			stepContainer.Env = append(stepContainer.Env, corev1.EnvVar{
				Name:  k,
				Value: v,
			})
		}

		if s.workingDir != "" {
			stepContainer.WorkingDir = s.workingDir
		}

		if s.securityContext != nil {
			stepContainer.SecurityContext = s.securityContext
		}

		p.Spec.Containers = append(p.Spec.Containers, stepContainer)
	}

	p.Spec.Volumes = append(p.Spec.Volumes, extraVolumes...)

	return p
}

func objectMeta(name, ns string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:        name,
		Namespace:   ns,
		Labels:      map[string]string{},
		Annotations: map[string]string{},
	}
}
