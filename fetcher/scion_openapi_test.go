// Copyright 2022 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fetcher

import (
	log "github.com/inconshreveable/log15"
	"os"
	"path/filepath"
	"testing"
)

func TestWipeInsecureSymlinks(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bootstrapper-openapi-tests_*")
	if err != nil {
		log.Error("Failed to create test directory for testrun", "dir", tmpDir, "err", err)
		return
	}

	certsDir := filepath.Join(tmpDir, "certs")
	if err = os.Mkdir(certsDir, 0775); err != nil {
		log.Error("Failed to create certs directory for testrun", "err", err)
		return
	}

	for _, f := range []string{"ISD42-B2-S3.trc", "ISD7-B5-S2.trc"} {
		if _, err := os.Create(filepath.Join(certsDir, f)); err != nil {
			log.Error("Failed to create test files for testrun", "err", err)
			return
		}
	}

	workingDir := filepath.Join(tmpDir, "bootstrapper")
	if err = os.Mkdir(workingDir, 0775); err != nil {
		log.Error("Failed to create bootstrapper directory for testrun", "err", err)
		return
	}

	trcsFromInsecureMode := []string{"ISD42-B2-S4.trc.insecure", "ISD7-B5-S1.trc.insecure"}
	for _, f := range trcsFromInsecureMode {
		if _, err := os.Create(filepath.Join(workingDir, f)); err != nil {
			log.Error("Failed to create test files for testrun", "err", err)
			return
		}
		err = os.Symlink(filepath.Join(workingDir, f), filepath.Join(certsDir, f))
		if err != nil {
			log.Error("Failed to symlink insecure TRC", "err", err)
			return
		}
	}

	// delete one of the TRC files from the insecure mode, get a dangling symlink
	if err = os.Remove(filepath.Join(workingDir, trcsFromInsecureMode[0])); err != nil {
		log.Error("Failed to remove insecure TRC", "err", err)
		return
	}

	// run the actual test, verifying that wiping symlinks from the insecure mode works
	if err = wipeInsecureSymlinks(tmpDir); err != nil {
		log.Error("Failed to wipe symlinks: wipeInsecureSymlinks", "err", err)
		t.FailNow()
	}

	// check that the TRC symlinks have been removed
	trcs, err := os.ReadDir(filepath.Join(tmpDir, "certs"))
	for _, trc := range trcs {
		fInfo, err := trc.Info()
		if err != nil {
			log.Error("Failed to get file info", "err", err)
		}
		if fInfo.Mode().IsRegular() {
			continue
		}
		if fInfo.Mode()&os.ModeSymlink != 1 {
			log.Error("Not all insecure TRC symlinks removed",
				"file", filepath.Join(tmpDir, "certs", trc.Name()))
			t.FailNow()
		}
	}
}
