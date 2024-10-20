package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const (
	partialSeedARN = "arn:aws:acm-pca:eu-west-2:111122223333:certificate-authority/dd2ad289-e690-44dc-9351-2e820bb15fa0"
	fullSeedARN    = "arn:aws:acm-pca:eu-west-2:111122223333:certificate-authority/df8941af-1ef7-4054-8518-b37e4b2e598c"
	fullSeedCert   = `-----BEGIN CERTIFICATE-----
MIIBczCCARigAwIBAgIRAPVP6Jkcp56VyCTIfv+MpEIwCgYIKoZIzj0EAwIwFzEV
MBMGA1UEAxMMRnVsbCBTZWVkIENBMB4XDTI0MTAyMDEyNTAyMVoXDTM0MTAxODEz
NTAyMVowFzEVMBMGA1UEAxMMRnVsbCBTZWVkIENBMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEOK3oNqlmwYpS5xoYIsCflcXWOlrfUUz2dVrRwh6xl57kdHSz/HdU
5dx97qVns3lLtWxy3mkLpWfM+ivqjZkrUqNFMEMwDgYDVR0PAQH/BAQDAgKEMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHOl6tES1b7s04X3CVMTftS/2f3i
MAoGCCqGSM49BAMCA0kAMEYCIQCNmcr/Y0IBbH70Bt6pgWCRGchCgXzHJVjmcqcS
YAw+qwIhALhScMixjl06YtIKyyBaPPkZKMFR4py+gH7CTiemzjJd
-----END CERTIFICATE-----
`
	e2eSeedARN = "arn:aws:acm-pca:eu-west-2:111122223333:certificate-authority/0634ece4-ec81-4bf1-8636-d9032f1e5eea"
)

func TestLoadFullSeeded(t *testing.T) {
	db, err := loadDB(filepath.Join(t.TempDir(), "db.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := loadAndSeed("testdata/fullseed.yaml", db, false); err != nil {
		t.Fatal(err)
	}

	var ca *certificateAuthority
	db.Read(func(data *state) {
		ca = data.CertificateAuthorities[fullSeedARN]
	})
	if ca == nil {
		t.Fatal("no ca seeded")
	}

	t.Logf("stored:\n%s\n\nseed:\n%s\n", ca.CAPem, fullSeedCert)

	if ca.CAPem != fullSeedCert {
		t.Error("different cert was seeded into state store")
	}
}

func TestSeedingFile(t *testing.T) {
	// create a working copy of the not fully seeded filt
	workfile := filepath.Join(t.TempDir(), "seed.yaml")
	if err := copyFile("testdata/partialseed.yaml", workfile); err != nil {
		t.Fatal(err)
	}

	runLoadAndSeed := func() *certificateAuthority {
		db, err := loadDB(filepath.Join(t.TempDir(), "db.json"))
		if err != nil {
			t.Fatal(err)
		}

		if err := loadAndSeed(workfile, db, false); err != nil {
			t.Fatal(err)
		}

		var ca *certificateAuthority
		db.Read(func(data *state) {
			ca = data.CertificateAuthorities[partialSeedARN]
		})
		return ca
	}

	origCa := runLoadAndSeed()
	if origCa == nil {
		t.Fatal("CA was not added to DB")
	}
	if origCa.CAPem == "" || origCa.PrivPem == "" {
		t.Fatal("CA cert/key was not added to DB")
	}

	for range 5 {
		sb, err := os.ReadFile(workfile)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("file:\n%s", string(sb))
		// redo the whole load path, ensuring each time the state is the same,
		// even with a fresh DB path (t.TmpDir is unique each call). The seed file
		// should have been updated, so each load should have the same data
		gotCa := runLoadAndSeed()
		if gotCa.CAPem != origCa.CAPem || gotCa.PrivPem != origCa.PrivPem {
			t.Error("re-loading partial file into new DB returned different results")
		}
	}
}

func copyFile(src, dst string) error {
	// why do i have to write this lol
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %v", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %v", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %v", err)
	}

	return nil
}
