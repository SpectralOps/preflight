package pkg

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/thoas/go-funk"
)

//nolint
const EMO_TIME = "⌛️"

//nolint
const EMO_CHECK = "✅"

//nolint
const EMO_FAILED = "❌"

type Porcelain struct {
}

func fmtSigs(sigs []Signature) string {
	return strings.Join(funk.Map(sigs, func(sig Signature) string {
		return sig.String()
	}).([]string), ", ")
}

func fmtLookups(sigs []Lookup) string {
	return strings.Join(funk.Map(sigs, func(lk Lookup) string {
		return lk.Name()
	}).([]string), ", ")
}

func (p *Porcelain) Start(pf *Preflight) {
	name := ""
	if len(pf.Lookup) > 1 { // first item is the empty lookup
		name = fmt.Sprintf(" with %s", fmtLookups(pf.Lookup[1:]))
	}
	fmt.Printf("%v Preflight starting%v\n", EMO_TIME, name)
}
func (p *Porcelain) RunOk() {
	fmt.Printf("%v Preflight verified\n", EMO_CHECK)
}

func (p *Porcelain) CheckFailed(check *CheckResult) {
	if check.ValidDigest == nil {

		green := color.New(color.FgGreen).SprintFunc()
		red := color.New(color.FgRed).SprintFunc()

		fmt.Printf(`%v Preflight failed:`, EMO_FAILED)
		fmt.Printf(` Digest does not match.

Expected: 
%v

Actual: 
%v
`,
			green(fmtSigs(check.ExpectedDigests)),
			red(check.ActualDigest.String()),
		)
	} else if check.LookupResult != nil && check.LookupResult.Vulnerable {
		fmt.Printf(`%v Preflight failed:`, EMO_FAILED)
		fmt.Printf(` Digest matches but marked as vulnerable.

Information:
`)
		fmt.Printf("  Vulnerability: %v\n", check.LookupResult.Message)
		fmt.Printf("  More: %v\n", check.LookupResult.Link)
	} else {
		fmt.Printf(`%v Preflight failed.`, EMO_FAILED)
	}
}
