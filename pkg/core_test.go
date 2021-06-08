package pkg

import (
	"testing"

	"github.com/alecthomas/assert"
)

func TestGoodMD5Check(t *testing.T) {
	pf := NewPreflight([]Lookup{&NoLookup{}})
	res, err := pf.Check("echo 'hello'", "md5=a849639cc38d82e3c0ac4e4dfd8186dd")
	assert.NoError(t, err)
	assert.Equal(t, true, res.Ok)
}
func TestGoodSHA1Check(t *testing.T) {
	pf := NewPreflight([]Lookup{&NoLookup{}})
	res, err := pf.Check("echo 'hello'", "sha1=098f8f78f1e13e2a2eee10d6974daebf892e4a71")
	assert.NoError(t, err)
	assert.Equal(t, true, res.Ok)
}
func TestGoodSHA256Check(t *testing.T) {
	pf := NewPreflight([]Lookup{&NoLookup{}})
	res, err := pf.Check("echo 'hello'", "sha256=3b084aa6ad2246428c9270825d8631e077b7e7c9bb16f6cafb482bc7fd63e348")
	assert.NoError(t, err)
	assert.Equal(t, true, res.Ok)
}
func TestGoodSHA256DefaultCheck(t *testing.T) {
	pf := NewPreflight([]Lookup{&NoLookup{}})
	res, err := pf.Check("echo 'hello'", "3b084aa6ad2246428c9270825d8631e077b7e7c9bb16f6cafb482bc7fd63e348")
	assert.NoError(t, err)
	assert.Equal(t, true, res.Ok)
}
func TestBadCheck(t *testing.T) {
	pf := NewPreflight([]Lookup{&NoLookup{}})
	res, err := pf.Check("abcd", "123")
	assert.NoError(t, err)
	sig := "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"
	assert.Equal(t, res.ActualDigest.SHA256, sig)
	assert.Nil(t, res.ValidDigest)
	assert.Equal(t, res.ExpectedDigests[0].content, "123")
	assert.Equal(t, res.ExpectedDigests[0].digest, "sha256")
	assert.Equal(t, false, res.Ok)
}

func TestGoodCheck(t *testing.T) {
	pf := NewPreflight([]Lookup{&NoLookup{}})
	sig := "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"
	res, err := pf.Check("abcd", sig)
	assert.NoError(t, err)
	assert.Equal(t, res.ActualDigest.SHA256, sig)
	assert.Equal(t, res.ValidDigest.content, sig)
	assert.Equal(t, res.ExpectedDigests[0].content, sig)
	assert.Equal(t, res.ExpectedDigests[0].digest, "sha256")
	assert.Equal(t, true, res.Ok)
}

type FakeLookup struct {
}

func (f *FakeLookup) Name() string {
	return "Fake"
}

func (f *FakeLookup) Hash(digest Digest) (LookupResult, error) {
	return LookupResult{Vulnerable: true, Message: "vuln", Link: "https://example.com/1"}, nil
}
func TestVulnerableCheck(t *testing.T) {
	pf := NewPreflight([]Lookup{&NoLookup{}, &FakeLookup{}})
	sig := "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"
	res, err := pf.Check("abcd", sig)
	assert.NoError(t, err)
	assert.Equal(t, res.ActualDigest.SHA256, sig)
	assert.Equal(t, res.ExpectedDigests[0].content, sig)
	assert.Equal(t, res.ValidDigest.content, sig)
	assert.NotNil(t, res.LookupResult)
	assert.Equal(t, res.LookupResult.Vulnerable, true)
	assert.Equal(t, res.HasValidationVulns(), false)
	assert.Equal(t, res.HasLookupVulns(), true)
	assert.Equal(t, false, res.Ok)
}
func ExampleExecBadDigest() {
	pf := NewPreflight([]Lookup{&NoLookup{}, &FakeLookup{}})
	pf.Exec([]string{"../test.sh"}, "123")

	// Output:
	// 	⌛️ Preflight starting with Fake
	// 	Preflight failed: Digest does not match.

	//   Expected:
	//   sha256=123

	//   Actual:
	//   sha256=3b084aa6ad2246428c9270825d8631e077b7e7c9bb16f6cafb482bc7fd63e348
	//   OR: sha1=098f8f78f1e13e2a2eee10d6974daebf892e4a71
	//   OR: md5=a849639cc38d82e3c0ac4e4dfd8186dd
}

func ExampleExecVuln() {
	pf := NewPreflight([]Lookup{&NoLookup{}, &FakeLookup{}})
	pf.Exec([]string{"../test.sh"}, "fe6d02cf15642ff8d5f61cad6d636a62fd46a5e5a49c06733fece838f5fa9d85")
	// Output:
	// ⌛️ Preflight starting with Fake
	// ❌ Preflight failed: Digest matches but marked as vulnerable.
	//
	// Information:
	//   Vulnerability: vuln
	//   More: https://example.com/1
}

func ExampleExecOk() {
	pf := NewPreflight([]Lookup{&NoLookup{}})
	pf.Exec([]string{"../test.sh"}, "fe6d02cf15642ff8d5f61cad6d636a62fd46a5e5a49c06733fece838f5fa9d85")

	// Output:
	// ⌛️ Preflight starting
	// ✅ Preflight verified
	// hello
}

func ExampleExecPipedBadDigest() {
	pf := NewPreflight([]Lookup{&NoLookup{}, &FakeLookup{}})
	pf.ExecPiped("echo 'hello'", "123")

	// Output:
	// 	⌛️ Preflight starting with Fake
	// 	Preflight failed: Digest does not match.

	//   Expected:
	//   sha256=123

	//   Actual:
	//   sha256=3b084aa6ad2246428c9270825d8631e077b7e7c9bb16f6cafb482bc7fd63e348
	//   OR: sha1=098f8f78f1e13e2a2eee10d6974daebf892e4a71
	//   OR: md5=a849639cc38d82e3c0ac4e4dfd8186dd
}

func ExampleExecPipedVuln() {
	pf := NewPreflight([]Lookup{&NoLookup{}, &FakeLookup{}})
	pf.ExecPiped("echo 'hello'", "3b084aa6ad2246428c9270825d8631e077b7e7c9bb16f6cafb482bc7fd63e348")
	// Output:
	// ⌛️ Preflight starting with Fake
	// ❌ Preflight failed: Digest matches but marked as vulnerable.
	//
	// Information:
	//   Vulnerability: vuln
	//   More: https://example.com/1
}

func ExampleExecPipedOk() {
	pf := NewPreflight([]Lookup{&NoLookup{}})
	pf.ExecPiped("echo 'hello'", "3b084aa6ad2246428c9270825d8631e077b7e7c9bb16f6cafb482bc7fd63e348")

	// Output:
	// ⌛️ Preflight starting
	// ✅ Preflight verified
	// hello
}

func ExampleFileLookup() {
	lookup, _ := NewFileLookup("../file_lookup_list.txt")
	pf := NewPreflight([]Lookup{&NoLookup{}, lookup})
	pf.ExecPiped("echo 'hello'", "3b084aa6ad2246428c9270825d8631e077b7e7c9bb16f6cafb482bc7fd63e348")

	// Output:
	// ⌛️ Preflight starting with file lookup: ../file_lookup_list.txt
	// ✅ Preflight verified
	// hello
}

func TestCreateSignature(t *testing.T) {
	s := createSignature("sha256=46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33 # foobaz")
	assert.Equal(t, s.String(), "sha256=46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33")
	s = createSignature("46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33 # foobar")
	assert.Equal(t, s.String(), "sha256=46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33")
	s = createSignature("46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33 # foobar v2")
	assert.Equal(t, s.String(), "sha256=46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33")
	s = createSignature("46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33 foobar v2")
	assert.Equal(t, s.String(), "sha256=46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33")
	s = createSignature("46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33")
	assert.Equal(t, s.String(), "sha256=46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33")
	s = createSignature("   46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33")
	assert.Equal(t, s.String(), "sha256=46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33")
	s = createSignature("   sha256=46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33 ")
	assert.Equal(t, s.String(), "sha256=46c2cf18d822cc3f310b320240259d6735d4a3ae06d82cb705a3e0e8d520f33")

}
