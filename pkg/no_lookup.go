package pkg

type NoLookup struct {
}

func (p *NoLookup) Name() string {
	return ""
}

func (p *NoLookup) Hash(digest Digest) LookupResult {
	return LookupResult{Vulnerable: false}
}
