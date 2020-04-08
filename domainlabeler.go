package certificate_searcher

import (
	"strings"
	"unicode"
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

type DomainLabeler interface {
	LabelDomain(domain string) []DomainLabel
}

type TypoSquattingLabeler struct {
	BaseDomains *[]string
	MissingDotDomains map[string]struct{}
	CharOmissionDomains map[string]struct{}
	CharPermutationDomains map[string]struct{}
	CharSubstitutionDomains map[string]struct{}
	CharDuplicationDomains map[string]struct{}
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

		for idx, char := range domain {
			if !unicode.IsLetter(char) {
				continue
			}

			omittedCharDomain := domain[:idx] + domain[idx+1:]
			tsl.CharOmissionDomains[omittedCharDomain] = struct{}{}
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


	return domainLabel
}