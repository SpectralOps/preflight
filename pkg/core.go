// execute a command, and take care to sanitize the child process environment (conditionally)
package pkg

import (
	//nolint
	"crypto/md5"
	//nolint
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

type Digest struct {
	SHA1   string
	SHA256 string
	MD5    string
}

func (d *Digest) Verify(s Signature) (ok bool, content string) {
	switch s.digest {
	case "sha1":
		return d.SHA1 == s.content, d.SHA1
	case "md5":
		return d.MD5 == s.content, d.MD5
	default:
		return d.SHA256 == s.content, d.SHA256
	}
}

type Signature struct {
	content string
	digest  string
}

type CheckResult struct {
	Lookup         LookupResult
	ExpectedDigest string
	ActualDigest   string
	Ok             bool
}

func (c *CheckResult) Error() error {
	if c.Ok {
		return nil
	}
	if c.Lookup.Vulnerable {
		return fmt.Errorf("vulnerable digest: %v", c.ActualDigest)
	}
	return fmt.Errorf("digest mismatch: actual: %v, expected: %v", c.ActualDigest, c.ExpectedDigest)
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

func digestTuple(s, sig string) (Digest, Signature) {
	parts := strings.Split(sig, "=")
	signature := Signature{content: sig, digest: "sha256"}
	if len(parts) > 1 {
		signature = Signature{content: parts[1], digest: strings.ToLower(parts[0])}
	}

	digest := Digest{
		//nolint
		SHA1: fmt.Sprintf("%x", sha1.Sum([]byte(s))),
		//nolint
		MD5:    fmt.Sprintf("%x", md5.Sum([]byte(s))),
		SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(s))),
	}

	return digest, signature
}

func NewPreflight(lookup Lookup) *Preflight {
	return &Preflight{
		Lookup:    lookup,
		Porcelain: &Porcelain{},
	}
}

func (a *Preflight) Check(script, sig string) CheckResult {
	digest, signature := digestTuple(script, sig)
	lookup := a.Lookup.Hash(digest)
	verifyOk, actual := digest.Verify(signature)
	return CheckResult{
		Lookup:         lookup,
		ActualDigest:   actual,
		ExpectedDigest: signature.content,
		Ok:             verifyOk && !lookup.Vulnerable,
	}
}

// XXX: windows/powershell needs a different function
func (a *Preflight) ExecPiped(script, sig string) error {
	a.Porcelain.Start(a)
	check := a.Check(script, sig)
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
	check := a.Check(string(s), sig)
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
