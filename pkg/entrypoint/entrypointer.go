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

package entrypoint

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"github.com/tektoncd/pipeline/pkg/termination"
	"go.uber.org/zap"
)

// RFC3339 with millisecond
const (
	timeFormat      = "2006-01-02T15:04:05.000Z07:00"
	ContinueOnError = "continue"
	FailOnError     = "stopAndFail"
)

// Entrypointer holds fields for running commands with redirected
// entrypoints.
type Entrypointer struct {
	// Command is the original specified command and args.
	Command []string

	// WaitFiles is the set of files to wait for. If empty, execution
	// begins immediately.
	WaitFiles []string
	// WaitFileContent indicates the WaitFile should have non-zero size
	// before continuing with execution.
	WaitFileContent bool
	// PostFile is the file to write when complete. If not specified, no
	// file is written.
	PostFile string

	// Termination path is the path of a file to write the starting time of this endpopint
	TerminationPath string

	// Waiter encapsulates waiting for files to exist.
	Waiter Waiter
	// Runner encapsulates running commands.
	Runner Runner
	// PostWriter encapsulates writing files when complete.
	PostWriter PostWriter

	// Results is the set of files that might contain task results
	Results []string
	// Timeout is an optional user-specified duration within which the Step must complete
	Timeout *time.Duration
	// BreakpointOnFailure helps determine if entrypoint execution needs to adapt debugging requirements
	BreakpointOnFailure bool
	// OnError defines exiting behavior of the entrypoint
	// set it to "stopAndFail" to indicate the entrypoint to exit the taskRun if the container exits with non zero exit code
	// set it to "continue" to indicate the entrypoint to continue executing the rest of the steps irrespective of the container exit code
	OnError string
	// StepMetadataDir is the directory for a step where the step related metadata can be stored
	StepMetadataDir string
}

// Waiter encapsulates waiting for files to exist.
type Waiter interface {
	// Wait blocks until the specified file exists.
	Wait(file string, expectContent bool, breakpointOnFailure bool) error
}

// Runner encapsulates running commands.
type Runner interface {
	Run(ctx context.Context, args ...string) error
}

// PostWriter encapsulates writing a file when complete.
type PostWriter interface {
	// Write writes to the path when complete.
	Write(file, content string)
}

var xsvid *x509svid.SVID = nil

func getxsvid(client *workloadapi.Client) (*x509svid.SVID, error) {
	var err error = nil
	if xsvid == nil {
		backoffSeconds := 2
		for i := 0; i < 20; i += backoffSeconds {
			xsvid, err = client.FetchX509SVID(context.Background())
			if err == nil {
				break
			}
			time.Sleep(time.Duration(backoffSeconds) * time.Second)
		}

	}
	return xsvid, nil
}

// Go optionally waits for a file, runs the command, and writes a
// post file.
func (e Entrypointer) Go() error {
	prod, _ := zap.NewProduction()
	logger := prod.Sugar()

	output := []v1beta1.PipelineResourceResult{}
	defer func() {
		if wErr := termination.WriteMessage(e.TerminationPath, output); wErr != nil {
			logger.Fatalf("Error while writing message: %s", wErr)
		}
		_ = logger.Sync()
	}()

	for _, f := range e.WaitFiles {
		if err := e.Waiter.Wait(f, e.WaitFileContent, e.BreakpointOnFailure); err != nil {
			// An error happened while waiting, so we bail
			// *but* we write postfile to make next steps bail too.
			// In case of breakpoint on failure do not write post file.
			if !e.BreakpointOnFailure {
				e.WritePostFile(e.PostFile, err)
			}
			output = append(output, v1beta1.PipelineResourceResult{
				Key:        "StartedAt",
				Value:      time.Now().Format(timeFormat),
				ResultType: v1beta1.InternalTektonResultType,
			})
			return err
		}
	}

	output = append(output, v1beta1.PipelineResourceResult{
		Key:        "StartedAt",
		Value:      time.Now().Format(timeFormat),
		ResultType: v1beta1.InternalTektonResultType,
	})

	ctx := context.Background()
	var err error
	var client *workloadapi.Client = nil

	client, err = workloadapi.New(ctx, workloadapi.WithAddr("unix:///spiffe-workload-api/spire-agent.sock"))
	if err != nil {
		logger.Errorf("Spire workload API not initalized due to error: %s", err.Error())
	}

	if e.Timeout != nil && *e.Timeout < time.Duration(0) {
		err = fmt.Errorf("negative timeout specified")
	}

	if err == nil {
		var cancel context.CancelFunc
		if e.Timeout != nil && *e.Timeout != time.Duration(0) {
			ctx, cancel = context.WithTimeout(ctx, *e.Timeout)
			defer cancel()
		}
		err = e.Runner.Run(ctx, e.Command...)
		if err == context.DeadlineExceeded {
			output = append(output, v1beta1.PipelineResourceResult{
				Key:        "Reason",
				Value:      "TimeoutExceeded",
				ResultType: v1beta1.InternalTektonResultType,
			})
		}
	}

	var ee *exec.ExitError
	switch {
	case err != nil && e.BreakpointOnFailure:
		logger.Info("Skipping writing to PostFile")
	case e.OnError == ContinueOnError && errors.As(err, &ee):
		// with continue on error and an ExitError, write non-zero exit code and a post file
		exitCode := strconv.Itoa(ee.ExitCode())
		output = append(output, v1beta1.PipelineResourceResult{
			Key:        "ExitCode",
			Value:      exitCode,
			ResultType: v1beta1.InternalTektonResultType,
		})
		e.WritePostFile(e.PostFile, nil)
		e.WriteExitCodeFile(e.StepMetadataDir, exitCode)
	case err == nil:
		// if err is nil, write zero exit code and a post file
		e.WritePostFile(e.PostFile, nil)
		e.WriteExitCodeFile(e.StepMetadataDir, "0")
	default:
		// for a step without continue on error and any error, write a post file with .err
		e.WritePostFile(e.PostFile, err)
	}

	// strings.Split(..) with an empty string returns an array that contains one element, an empty string.
	// This creates an error when trying to open the result folder as a file.
	if len(e.Results) >= 1 && e.Results[0] != "" {
		if err := e.readResultsFromDisk(client); err != nil {
			logger.Fatalf("Error while handling results: %s", err)
		}
	}

	return err
}

func Sign(results []v1beta1.PipelineResourceResult, client *workloadapi.Client) ([]v1beta1.PipelineResourceResult, error) {
	xsvid, err := getxsvid(client)
	if err != nil {
		return nil, err
	}
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

func getmanifest(results []v1beta1.PipelineResourceResult) string {
	keys := []string{}
	for _, r := range results {
		keys = append(keys, r.Key)
	}
	return strings.Join(keys, ",")
}

func (e Entrypointer) readResultsFromDisk(client *workloadapi.Client) error {
	xsvid, err := getxsvid(client)
	if err != nil {
		return err
	}
	output := []v1beta1.PipelineResourceResult{}
	for _, resultFile := range e.Results {
		if resultFile == "" {
			continue
		}
		fileContents, err := ioutil.ReadFile(filepath.Join(pipeline.DefaultResultPath, resultFile))
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		// if the file doesn't exist, ignore it
		output = append(output, v1beta1.PipelineResourceResult{
			Key:        resultFile,
			Value:      string(fileContents),
			ResultType: v1beta1.TaskRunResultType,
		})
	}
<<<<<<< HEAD
	signed, err := Sign(output, client)
	if err != nil {
		return err
	}
	output = append(output, signed...)
=======

	if client != nil {
		signed, err := Sign(output, client)
		if err != nil {
			return err
		}
		output = append(output, signed...)
	}
	// get complete manifest of keys such that it can be verified
	manifest := getmanifest(output)
	if manifest != "" {
		output = append(output, v1beta1.PipelineResourceResult{
			Key:        "RESULT_MANIFEST",
			Value:      manifest,
			ResultType: v1beta1.TaskRunResultType,
		})
		manifestSig, err := signWithKey(xsvid, manifest)
		if err != nil {
			return err
		}
		output = append(output, v1beta1.PipelineResourceResult{
			Key:        "RESULT_MANIFEST.sig",
			Value:      base64.StdEncoding.EncodeToString(manifestSig),
			ResultType: v1beta1.TaskRunResultType,
		})
	}

>>>>>>> 2b69aa9bc (changed to use spiffe-csi)
	// push output to termination path
	if len(output) != 0 {
		if err := termination.WriteMessage(e.TerminationPath, output); err != nil {
			return err
		}
	}
	return nil
}

// BreakpointExitCode reads the post file and returns the exit code it contains
func (e Entrypointer) BreakpointExitCode(breakpointExitPostFile string) (int, error) {
	exitCode, err := ioutil.ReadFile(breakpointExitPostFile)
	if os.IsNotExist(err) {
		return 0, fmt.Errorf("breakpoint postfile %s not found", breakpointExitPostFile)
	}
	strExitCode := strings.TrimSuffix(string(exitCode), "\n")
	log.Println("Breakpoint exiting with exit code " + strExitCode)

	return strconv.Atoi(strExitCode)
}

// WritePostFile write the postfile
func (e Entrypointer) WritePostFile(postFile string, err error) {
	if err != nil && postFile != "" {
		postFile = fmt.Sprintf("%s.err", postFile)
	}
	if postFile != "" {
		e.PostWriter.Write(postFile, "")
	}
}

// WriteExitCodeFile write the exitCodeFile
func (e Entrypointer) WriteExitCodeFile(stepPath, content string) {
	exitCodeFile := filepath.Join(stepPath, "exitCode")
	e.PostWriter.Write(exitCodeFile, content)
}
