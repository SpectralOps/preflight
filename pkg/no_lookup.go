package pkg

type NoLookup struct {
}

func (p *NoLookup) Name() string {
	return ""
}

func (p *NoLookup) Hash(digest Digest) (LookupResult, error) {
	return LookupResult{Vulnerable: false}, nil
}
