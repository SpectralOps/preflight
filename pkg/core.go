// execute a command, and take care to sanitize the child process environment (conditionally)
package pkg

import (
	//nolint
	"crypto/md5"
	"errors"
	"net/http"

	//nolint
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/thoas/go-funk"
)

type Digest struct {
	SHA1   string
	SHA256 string
	MD5    string
}

func (d *Digest) Verify(s Signature) (ok bool, expectedHash string) {
	switch s.digest {
	case "sha1":
		return d.SHA1 == s.content, d.SHA1
	case "md5":
		return d.MD5 == s.content, d.MD5
	default:
		return d.SHA256 == s.content, d.SHA256
	}
}
func (d *Digest) String() string {
	return fmt.Sprintf("sha256=%v\nOR: sha1=%v\nOR: md5=%v", d.SHA256, d.SHA1, d.MD5)
}

type Signature struct {
	content string
	digest  string
}

func (s *Signature) String() string {
	return fmt.Sprintf("%v=%v", s.digest, s.content)
}

type CheckResult struct {
	LookupResult    *LookupResult
	ValidDigest     *Signature
	ExpectedDigests []Signature
	ActualDigest    Digest
	Ok              bool
}

func (c *CheckResult) Error() error {
	if c.Ok {
		return nil
	}

	if c.HasLookupVulns() {
		return fmt.Errorf("vulnerable digest: %v", c.ActualDigest)
	} else if c.HasValidationVulns() {
		return fmt.Errorf("digest mismatch: actual: %v, expected: %v", c.ActualDigest, c.ExpectedDigests)
	} else {
		return errors.New("unknown result error")
	}
}

func (c *CheckResult) HasValidationVulns() bool {
	return c.ValidDigest == nil && len(c.ExpectedDigests) > 0
}

func (c *CheckResult) HasLookupVulns() bool {
	return c.LookupResult != nil && c.LookupResult.Vulnerable
}

type Lookup interface {
	Hash(digest Digest) LookupResult
	Name() string
}

type LookupResult struct {
	Vulnerable bool
	Message    string
	Link       string
}

type Preflight struct {
	Lookup    Lookup
	Porcelain *Porcelain
}

func GetLookup() (Lookup, error) {
	if os.Getenv("PF_FILE_LOOKUP") != "" {
		return NewFileLookup(os.Getenv("PF_FILE_LOOKUP"))
	}

	return &NoLookup{}, nil
}

func createDigest(s string) Digest {
	return Digest{
		//nolint
		SHA1: fmt.Sprintf("%x", sha1.Sum([]byte(s))),
		//nolint
		MD5:    fmt.Sprintf("%x", md5.Sum([]byte(s))),
		SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(s))),
	}
}

func createSignature(sig string) Signature {
	parts := strings.Split(sig, "=")
	signature := Signature{content: sig, digest: "sha256"}
	if len(parts) > 1 {
		signature = Signature{content: parts[1], digest: strings.ToLower(parts[0])}
	}

	return signature
}

func digestTuple(s, sig string) (Digest, Signature) {
	signature := createSignature(sig)
	digest := createDigest(s)
	return digest, signature
}

func NewPreflight(lookup Lookup) *Preflight {
	return &Preflight{
		Lookup:    lookup,
		Porcelain: &Porcelain{},
	}
}

func (a *Preflight) Check(script, siglist string) (*CheckResult, error) {
	sigs, err := parsehashList(siglist)
	if err != nil {
		return nil, err
	}
	digest := createDigest(script)

	res := funk.Find(sigs, func(s Signature) bool {
		ok, _ := digest.Verify(s)
		return ok
	})
	if res == nil {
		return &CheckResult{
			ExpectedDigests: sigs,
			ActualDigest:    digest,
			ValidDigest:     nil,
			Ok:              false,
		}, nil
	}

	validDigest := res.(Signature)
	// parseHashlist(sig) -> []Signature
	// check should return err, wired by parseHashlist + hash lookup
	// XXX untangle the digest tuple:
	// createDigest
	// parseSignature, accept sig []string
	// "verify" a signature
	// "validate" a hash
	// 0. get digest object
	// 1. parse all digs, then verify them. if one passes, we're OK
	// 2. next, the one that passes we want to lookup
	lookup := a.Lookup.Hash(digest)
	return &CheckResult{
		ExpectedDigests: sigs,
		ActualDigest:    digest,
		ValidDigest:     &validDigest,
		LookupResult:    &lookup,
		Ok:              !lookup.Vulnerable,
	}, nil
}

// XXX: windows/powershell needs a different function
func (a *Preflight) ExecPiped(script, sig string) error {
	a.Porcelain.Start(a)
	check, err := a.Check(script, sig)
	if err != nil {
		return err
	}
	if !check.Ok {
		a.Porcelain.CheckFailed(check)
		return check.Error()
	}
	a.Porcelain.RunOk()

	command := exec.Command("/bin/sh")
	command.Stdin = strings.NewReader(script)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func (a *Preflight) Exec(args []string, sig string) error {
	a.Porcelain.Start(a)
	s, err := ioutil.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("cannot open %v: %v", args[0], err)
	}
	check, err := a.Check(string(s), sig)
	if err != nil {
		return err
	}

	if !check.Ok {
		a.Porcelain.CheckFailed(check)
		return check.Error()
	}

	a.Porcelain.RunOk()

	//nolint
	command := exec.Command(args[0], args[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func parsehashList(hashArg string) ([]Signature, error) {
	var sigs []string
	if strings.Contains(hashArg, ",") {
		sigs = strings.Split(hashArg, ",")
	} else if strings.HasPrefix(hashArg, "http") {
		resp, err := http.Get(hashArg) //nolint
		if err != nil {
			return nil, fmt.Errorf("cannot parse hash URL: %v", err)
		}
		defer resp.Body.Close()
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("cannot read hash URL content: %v", err)
		}
		sigs = strings.Split(string(res), "\n")
	} else {
		sigs = []string{hashArg}
	}

	return funk.Map(sigs, createSignature).([]Signature), nil
}
