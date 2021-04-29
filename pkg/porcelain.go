package pkg

import (
	"fmt"

	"github.com/fatih/color"
)

//nolint
const EMO_TIME = "⌛️"

//nolint
const EMO_CHECK = "✅"

//nolint
const EMO_FAILED = "❌"

type Porcelain struct {
}

func (p *Porcelain) Start(pf *Preflight) {
	name := pf.Lookup.Name()
	if name != "" {
		name = fmt.Sprintf(" with %s", name)
	}
	fmt.Printf("%v Preflight starting%v\n", EMO_TIME, name)
}
func (p *Porcelain) RunOk() {
	fmt.Printf("%v Preflight verified\n", EMO_CHECK)
}

func (p *Porcelain) CheckFailed(check CheckResult) {
	if check.ActualDigest != check.ExpectedDigest {

		green := color.New(color.FgGreen).SprintFunc()
		red := color.New(color.FgRed).SprintFunc()

		fmt.Printf(`%v Preflight failed:`, EMO_FAILED)
		fmt.Printf(` Digest does not match.

   Expected: %v
   Actual: %v
`,
			green(check.ExpectedDigest),
			red(check.ActualDigest),
		)
	} else if check.Lookup.Vulnerable {
		fmt.Printf(`%v Preflight failed:`, EMO_FAILED)
		fmt.Printf(` Digest matches but marked as vulnerable.

Information:
`)
		fmt.Printf("  Vulnerability: %v\n", check.Lookup.Message)
		fmt.Printf("  More: %v\n", check.Lookup.Link)
	} else {
		fmt.Printf(`%v Preflight failed.`, EMO_FAILED)
	}
}
