package certificate_searcher

import (
	"fmt"
	"strings"
)

type CertStats struct {
	ParentSPKISubjectCerts map[string]map[string]struct{}
}

func (c CertStats) String() string {
	var str strings.Builder
	str.WriteString(fmt.Sprintf("%d total subject SPKI subjects\n", len(c.ParentSPKISubjectCerts)))

	for spkiSubject, noCTFingerprints := range c.ParentSPKISubjectCerts {
		str.WriteString(fmt.Sprintf("%s,%d\n", spkiSubject, len(noCTFingerprints)))
	}

	return str.String()
}

type CertInfo struct {
	TBSNoCTFingerprint string
	ParentSPKISubject string
}