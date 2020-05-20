package certificate_searcher

import (
	"encoding/hex"
	"fmt"
	"github.com/cespare/xxhash"
	"github.com/steakknife/bloomfilter"
	"log"
	"strings"
)

type CertStats struct {
	NoCTFingerprints        *bloomfilter.Filter
	ParentSPKISubjectCounts map[string]uint64
}

const maxElements uint64 = 10000000000
const probCollision float64 = 0.000000001

func NewCertStats() *CertStats {
	bf, err := bloomfilter.NewOptimal(maxElements, probCollision)
	if err != nil {
		log.Fatal(err)
	}

	return &CertStats{
		NoCTFingerprints:        bf,
		ParentSPKISubjectCounts: make(map[string]uint64),
	}
}

// Adds the parent/child if not currently in the Bloom filter, returns whether added or not (already seen)
func (c *CertStats) AddParentChild(parentSPKI []byte, childTBSNoCT []byte) bool {
	parentSPKIStr := hex.EncodeToString(parentSPKI)
	if _, present := c.ParentSPKISubjectCounts[parentSPKIStr]; !present {
		c.ParentSPKISubjectCounts[parentSPKIStr] = 0
	}

	hash := xxhash.New()
	hash.Write(childTBSNoCT)

	if c.NoCTFingerprints.Contains(hash) {
		return true
	}

	c.NoCTFingerprints.Add(hash)
	c.ParentSPKISubjectCounts[parentSPKIStr] += 1
	return false
}

func (c CertStats) String() string {
	var str strings.Builder
	total := uint64(0)
	for _, certificateCount := range c.ParentSPKISubjectCounts {
		total += certificateCount
	}

	str.WriteString(fmt.Sprintf("%d total subject SPKI subjects, %d total certificates (TBSNoCT)\n", len(c.ParentSPKISubjectCounts), total))

	for spkiSubject, certificateCount := range c.ParentSPKISubjectCounts {
		str.WriteString(fmt.Sprintf("%s,%d\n", spkiSubject, certificateCount))
	}

	return str.String()
}

type CertInfo struct {
	TBSNoCTFingerprint []byte
	ParentSPKISubject  []byte
}

func NewCertInfo(noCTFingerprint, parentSPKISubjFingerprint[]byte) *CertInfo {
	certFP := make([]byte, len(noCTFingerprint))
	parentFP := make([]byte, len(parentSPKISubjFingerprint))

	copy(certFP, noCTFingerprint)
	copy(parentFP, parentSPKISubjFingerprint)

	return &CertInfo{
		TBSNoCTFingerprint: certFP,
		ParentSPKISubject: parentFP,
	}
}
