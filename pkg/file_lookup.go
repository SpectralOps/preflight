package pkg

import (
	"fmt"
	"io/ioutil"
	"strings"
)

//nolint
const FILE_ENV_KEY = "PF_FILE_LOOKUP"

type FileLookup struct {
	content string
	file    string
}

func NewFileLookup(f string) (Lookup, error) {
	content, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("file lookup: cannot read file: %v", err)
	}
	return &FileLookup{
		content: string(content),
		file:    f,
	}, nil
}
func (p *FileLookup) Name() string {
	return fmt.Sprintf("file lookup: %v", p.file)
}
func (p *FileLookup) Hash(digest Digest) (LookupResult, error) {
	if strings.Contains(p.content, digest.SHA1) ||
		strings.Contains(p.content, digest.MD5) ||
		strings.Contains(p.content, digest.SHA256) {

		return LookupResult{
			Vulnerable: true,
			Message:    "Hash was found in a vulnerable digest list",
			Link:       p.file,
		}, nil
	}
	return LookupResult{}, nil
}
