package pkg

import (
	"fmt"
	"os"
	"strings"

	vt "github.com/VirusTotal/vt-go"
)

//nolint
const VT_ENV_KEY = "PF_VT_TOKEN"

type VirusTotalLookup struct {
	client *vt.Client
}

func NewVirusTotalLookup(f string) (Lookup, error) {
	apikey := os.Getenv(VT_ENV_KEY)
	client := vt.NewClient(apikey)

	return &VirusTotalLookup{
		client: client,
	}, nil
}
func (p *VirusTotalLookup) Name() string {
	return "VirusTotal"
}
func (p *VirusTotalLookup) Hash(digest Digest) (LookupResult, error) {
	file, err := p.client.GetObject(vt.URL("files/%s", digest.SHA256))
	if err != nil {
		if !strings.Contains(err.Error(), "not found") { // if not found, it's ok
			return LookupResult{}, fmt.Errorf("virustotal: %v", err)
		}
	}

	if file == nil {
		// file is OK because it was not found
		return LookupResult{}, nil
	}

	m, _ := file.GetInt64("last_analysis_stats.malicious")
	s, _ := file.GetInt64("last_analysis_stats.suspicious")

	return LookupResult{
		Vulnerable: m+s > 0,
		Message:    fmt.Sprintf("VirusTotal stats - malicious: %v, suspicious %v", m, s),
		Link:       fmt.Sprintf("https://www.virustotal.com/gui/file/%v/detection", digest.SHA256),
	}, nil
}
