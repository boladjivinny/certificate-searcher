package certificate_searcher

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type DomainLabel int

const (
	// No identifiable label
	UNLABELED DomainLabel = iota
	// Seven Months’ Worth of Mistakes: A Longitudinal Study of Typosquatting Abuse - NDSS 2015
	TYPOSQUATTING_MISSING_DOT
	TYPOSQUATTING_CHAR_OMISSION
	TYPOSQUATTING_CHAR_PERMUTATION
	TYPOSQUATTING_CHAR_SUBSTITUTION
	TYPOSQUATTING_CHAR_DUPLICATION
	// You Are Who You Appear to Be: A Longitudinal Study of Domain Impersonation in TLS Certificates - CCS 2019
	TARGET_EMBEDDING
	// Hiding in Plain Sight: A Longitudinal Study of Combosquatting Abuse - CCS 2017
	COMBOSQUATTING
	// Cutting through the Confusion: A Measurement Study of Homograph Attacks - ATC 2006
	HOMOGRAPH
	// Needle in a Haystack: Tracking Down Elite Phishing Domains in the Wild - IMC 2018
	WRONGTLD
	// Bitsquatting: Exploiting bit-flips for fun, or profit? WWW 2013
	BITSQUATTING
	// Phishtank
	PHISHTANK
	// SSLBL
	SSL_BLACKLIST
	// Google SafeBrowsing
	GOOGLE_SAFEBROWSING
)

func (dl DomainLabel) String() string {
	return [...]string{
		"Unlabeled",
		"TYPOSQUATTING_MISSING_DOT",
		"TYPOSQUATTING_CHAR_OMISSION",
		"TYPOSQUATTING_CHAR_PERMUTATION",
		"TYPOSQUATTING_CHAR_SUBSTITUTION",
		"TYPOSQUATTING_CHAR_DUPLICATION",
		"TARGET_EMBEDDING",
		"COMBOSQUATTING",
		"HOMOGRAPH",
		"WRONGTLD",
		"BITSQUATTING",
		"PHISHTANK",
		"SSL_BLACKLIST",
		"GOOGLE_SAFEBROWSING",
	}[dl]
}

type DomainLabeler interface {
	LabelDomain(domain string) []DomainLabel
}

type TypoSquattingLabeler struct {
	BaseDomains             *[]string
	MissingDotDomains       map[string]struct{}
	CharOmissionDomains     map[string]struct{}
	CharPermutationDomains  map[string]struct{}
	CharSubstitutionDomains map[string]struct{}
	CharDuplicationDomains  map[string]struct{}
}

func NewTypoSquattingLabeler(baseDomains *[]string) *TypoSquattingLabeler {
	tsl := &TypoSquattingLabeler{
		BaseDomains:             baseDomains,
		MissingDotDomains:       make(map[string]struct{}),
		CharOmissionDomains:     make(map[string]struct{}),
		CharPermutationDomains:  make(map[string]struct{}), // TODO
		CharSubstitutionDomains: make(map[string]struct{}), // TODO
		CharDuplicationDomains:  make(map[string]struct{}), // TODO
	}

	for _, domain := range *baseDomains {
		if strings.HasPrefix(domain, "www.") {
			tsl.MissingDotDomains["www"+domain[4:]] = struct{}{}
		}

		runeDomain := []rune(domain)

		for idx, r := range runeDomain {
			if !unicode.IsLetter(r) {
				continue
			}

			tempSlice := append(make([]rune, 0), runeDomain[:idx]...)
			omittedCharDomain := string(append(tempSlice, runeDomain[idx+1:]...))
			tsl.CharOmissionDomains[omittedCharDomain] = struct{}{}
		}

		for idx, char := range runeDomain {
			if idx >= len(domain)-1 {
				break
			}
			if !unicode.IsLetter(char) || !unicode.IsLetter(runeDomain[idx+1]) {
				continue
			}
			if runeDomain[idx] == runeDomain[idx+1] {
				continue
			}

			tempSlice := append(make([]rune, 0), runeDomain[:idx]...)
			tempSlice = append(tempSlice, runeDomain[idx+1], runeDomain[idx])
			permutedCharDomain := string(append(tempSlice, runeDomain[idx+2:]...))
			tsl.CharPermutationDomains[permutedCharDomain] = struct{}{}
		}

		for idx, char := range runeDomain {
			if !unicode.IsLetter(char) {
				continue
			}

			tempSlice := append(make([]rune, 0), runeDomain[:idx]...)
			tempSlice = append(tempSlice, runeDomain[idx])
			duplicatedCharDomain := string(append(tempSlice, runeDomain[idx:]...))
			tsl.CharDuplicationDomains[duplicatedCharDomain] = struct{}{}
		}

		for idx, char := range runeDomain {
			if !QwertyAlphanumeric(char) {
				continue
			}

			adjacentChars, err := QwertyAdjacentRunes(char)
			if err != nil {
				continue
			}

			for _, adjacentChar := range adjacentChars {
				tempSlice := append(make([]rune, 0), runeDomain[:idx]...)
				tempSlice = append(tempSlice, adjacentChar)
				substitutedCharDomain := string(append(tempSlice, runeDomain[idx+1:]...))
				tsl.CharSubstitutionDomains[substitutedCharDomain] = struct{}{}
			}
		}
	}

	return tsl
}

func (t *TypoSquattingLabeler) LabelDomain(domain string) []DomainLabel {
	domainLabel := make([]DomainLabel, 0)

	if _, present := t.MissingDotDomains[domain]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_MISSING_DOT)
	}
	if _, present := t.CharOmissionDomains[domain]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_CHAR_OMISSION)
	}
	if _, present := t.CharPermutationDomains[domain]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_CHAR_PERMUTATION)
	}
	if _, present := t.CharDuplicationDomains[domain]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_CHAR_DUPLICATION)
	}
	if _, present := t.CharSubstitutionDomains[domain]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_CHAR_SUBSTITUTION)
	}

	return domainLabel
}

type TargetEmbeddingLabeler struct {
	BaseDomains   *[]string
	CombinedRegex *regexp.Regexp
	RegexString   string
}

func NewTargetEmbeddingLabeler(baseDomains *[]string) *TargetEmbeddingLabeler {
	tel := &TargetEmbeddingLabeler{
		BaseDomains: baseDomains,
	}

	regexExpressions := make([]string, len(*baseDomains))
	for idx, domain := range *baseDomains {
		regexDomain := regexp.QuoteMeta(domain)
		regexExpressions[idx] = `[-\.]?` + regexDomain + `[-\.]`
	}
	tel.RegexString = strings.Join(regexExpressions, "|")
	tel.CombinedRegex = regexp.MustCompile(strings.Join(regexExpressions, "|"))

	return tel
}

func (t *TargetEmbeddingLabeler) LabelDomain(domain string) []DomainLabel {
	matches := t.CombinedRegex.FindAllString(domain, -1)
	if matches != nil {
		return []DomainLabel{TARGET_EMBEDDING}
	}

	return nil
}

type HomoGraphLabeler struct {
}

func NewHomoGraphLabeler(baseDomains *[]string) *HomoGraphLabeler {
	tel := &HomoGraphLabeler{

	}
	return tel
}

func (t *HomoGraphLabeler) LabelDomain(domain string) {

}

type BitSquattingLabeler struct {
	BaseDomains        *[]string
	BitSquattedDomains map[string]struct{}
}

func uint8Exp2(pow int) uint8 {
	output := uint8(1)
	for i := 0; i < pow; i++ {
		output = output * 2
	}

	return output
}

func NewBitSquattingLabeler(baseDomains *[]string) *BitSquattingLabeler {
	bsl := &BitSquattingLabeler{
		BaseDomains:        baseDomains,
		BitSquattedDomains: make(map[string]struct{}),
	}
	for _, domain := range *baseDomains {
		for idx := range domain {
			for offset := 0; offset < 8; offset++ {
				tempSlice := make([]byte, len(domain))
				tempSlice = append(tempSlice, domain[:idx]...)
				bitFlippedByte := uint8Exp2(offset) ^ domain[idx]
				tempSlice = append(tempSlice, bitFlippedByte)
				bitFlippedDomain :=append(tempSlice, domain[idx+1:]...)

				if utf8.Valid(bitFlippedDomain) {
					bsl.BitSquattedDomains[string(bitFlippedDomain)] = struct{}{}
				}
			}
		}
	}
	return bsl
}

func (b *BitSquattingLabeler) LabelDomain(domain string) []DomainLabel {
	domainLabel := make([]DomainLabel, 0)

	if _, present := b.BitSquattedDomains[domain]; present {
		domainLabel = append(domainLabel, BITSQUATTING)
	}

	return domainLabel
}

type WrongTLDLabeler struct {
}

func NewWrongTLDLabeler(baseDomains *[]string) *WrongTLDLabeler {
	tel := &WrongTLDLabeler{

	}
	return tel
}

func (t *WrongTLDLabeler) LabelDomain(domain string) {

}

type ComboSquattingLabeler struct {
}

func NewComboSquattingLabeler(baseDomains *[]string) *ComboSquattingLabeler {
	tel := &ComboSquattingLabeler{

	}
	return tel
}

func (t *ComboSquattingLabeler) LabelDomain(domain string) {

}
