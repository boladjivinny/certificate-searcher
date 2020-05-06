package certificate_searcher

import (
	"bufio"
	"fmt"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
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

type BaseDomains map[string]struct{}
type Mutation string
type MutatedDomains map[Mutation]BaseDomains

type DomainMutator interface {
	GetMutations() MutatedDomains
}

func AddMutation(mutatedDomains MutatedDomains, mutation Mutation, baseDomain string) {
	if _, present := mutatedDomains[mutation]; !present {
		mutatedDomains[mutation] = make(BaseDomains)
	}
	mutatedDomains[mutation][baseDomain] = struct{}{}
}

type TypoSquattingLabeler struct {
	BaseDomains             *[]string
	MissingDotDomains       MutatedDomains
	CharOmissionDomains     MutatedDomains
	CharPermutationDomains  MutatedDomains
	CharSubstitutionDomains MutatedDomains
	CharDuplicationDomains  MutatedDomains
	AllMutatedDomains MutatedDomains
}

func NewTypoSquattingLabeler(baseDomains *[]string) *TypoSquattingLabeler {
	tsl := &TypoSquattingLabeler{
		BaseDomains:             baseDomains,
		MissingDotDomains:       make(MutatedDomains),
		CharOmissionDomains:     make(MutatedDomains),
		CharPermutationDomains:  make(MutatedDomains),
		CharSubstitutionDomains: make(MutatedDomains),
		CharDuplicationDomains:  make(MutatedDomains),
		AllMutatedDomains: make(MutatedDomains),
	}

	for _, domain := range *baseDomains {
		if strings.HasPrefix(domain, "www.") {
			AddMutation(tsl.MissingDotDomains, Mutation("www"+domain[4:]), domain)
			AddMutation(tsl.AllMutatedDomains, Mutation("www"+domain[4:]), domain)
		}

		runeDomain := []rune(domain)

		for idx, r := range runeDomain {
			if !unicode.IsLetter(r) {
				continue
			}

			tempSlice := append(make([]rune, 0), runeDomain[:idx]...)
			omittedCharDomain := string(append(tempSlice, runeDomain[idx+1:]...))
			AddMutation(tsl.CharOmissionDomains, Mutation(omittedCharDomain), domain)
			AddMutation(tsl.AllMutatedDomains, Mutation(omittedCharDomain), domain)
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
			AddMutation(tsl.CharPermutationDomains, Mutation(permutedCharDomain), domain)
			AddMutation(tsl.AllMutatedDomains, Mutation(permutedCharDomain), domain)
		}

		for idx, char := range runeDomain {
			if !unicode.IsLetter(char) {
				continue
			}

			tempSlice := append(make([]rune, 0), runeDomain[:idx]...)
			tempSlice = append(tempSlice, runeDomain[idx])
			duplicatedCharDomain := string(append(tempSlice, runeDomain[idx:]...))
			AddMutation(tsl.CharDuplicationDomains, Mutation(duplicatedCharDomain), domain)
			AddMutation(tsl.AllMutatedDomains, Mutation(duplicatedCharDomain), domain)
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
				AddMutation(tsl.CharSubstitutionDomains, Mutation(substitutedCharDomain), domain)
				AddMutation(tsl.AllMutatedDomains, Mutation(substitutedCharDomain), domain)
			}
		}
	}

	return tsl
}

func (t *TypoSquattingLabeler) LabelDomain(domain string) []DomainLabel {
	domainLabel := make([]DomainLabel, 0)
	mutation := Mutation(domain)

	if _, present := t.MissingDotDomains[mutation]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_MISSING_DOT)
	}
	if _, present := t.CharOmissionDomains[mutation]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_CHAR_OMISSION)
	}
	if _, present := t.CharPermutationDomains[mutation]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_CHAR_PERMUTATION)
	}
	if _, present := t.CharDuplicationDomains[mutation]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_CHAR_DUPLICATION)
	}
	if _, present := t.CharSubstitutionDomains[mutation]; present {
		domainLabel = append(domainLabel, TYPOSQUATTING_CHAR_SUBSTITUTION)
	}

	return domainLabel
}

func (t * TypoSquattingLabeler) GetMutations() MutatedDomains {
	return t.AllMutatedDomains
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
	BaseDomainMap map[string]struct{}
}

func NewHomoGraphLabeler(baseDomains *[]string) *HomoGraphLabeler {
	domains := make(map[string]struct{})

	for _, domain := range *baseDomains {
		domains[domain] = struct{}{}
	}

	hl := &HomoGraphLabeler{
		BaseDomainMap: domains,
	}

	return hl
}

func (t *HomoGraphLabeler) LabelDomain(domain string) []DomainLabel {
	domain = strings.ToLower(domain)
	IDN_ACE := "xn--" // IDN ASCII Compatible Encoding
	hasPunycode := strings.Contains(domain, IDN_ACE)
	hasASCIIHomograph := strings.ContainsAny(domain, string(ASCII_HOMOGLYPHS))
	if !hasPunycode && !hasASCIIHomograph {
		return []DomainLabel{}
	}

	var unicodeStr string
	var err error
	if hasPunycode {
		p := idna.New()
		unicodeStr, err = p.ToUnicode(domain)
		if err != nil {
			fmt.Printf("Error: invalid punycode: %s", domain)
		}
	} else {
		unicodeStr = domain
	}

	for _, homograph := range GetASCIIHomographs(unicodeStr) {
		if _, present := t.BaseDomainMap[homograph]; present {
			return []DomainLabel{HOMOGRAPH}
		}
	}

	return []DomainLabel{}
}

type BitSquattingLabeler struct {
	BaseDomains        *[]string
	BitSquattedDomains MutatedDomains
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
		BitSquattedDomains: make(MutatedDomains),
	}
	for _, domain := range *baseDomains {
		for idx := range domain {
			for offset := 0; offset < 8; offset++ {
				tempSlice := make([]byte, 0)
				tempSlice = append(tempSlice, domain[:idx]...)
				bitFlippedByte := uint8Exp2(offset) ^ domain[idx]
				tempSlice = append(tempSlice, bitFlippedByte)
				bitFlippedDomain := append(tempSlice, domain[idx+1:]...)

				if utf8.Valid(bitFlippedDomain) && ValidHostname(string(bitFlippedDomain)) {
					AddMutation(bsl.BitSquattedDomains, Mutation(bitFlippedDomain), domain)
				}
			}
		}
	}

	return bsl
}

func (b *BitSquattingLabeler) LabelDomain(domain string) []DomainLabel {
	domainLabel := make([]DomainLabel, 0)
	mutation := Mutation(domain)

	if _, present := b.BitSquattedDomains[mutation]; present {
		domainLabel = append(domainLabel, BITSQUATTING)
	}

	return domainLabel
}

func (b *BitSquattingLabeler) GetMutations() MutatedDomains {
	return b.BitSquattedDomains
}


type WrongTLDLabeler struct {
	BaseDomains     *[]string
	OneOrTwoTLDs    map[string]struct{}
	WrongTLDDomains MutatedDomains
}

func NewWrongTLDLabeler(baseDomains *[]string) *WrongTLDLabeler {
	wtl := &WrongTLDLabeler{
		BaseDomains:     baseDomains,
		WrongTLDDomains: make(MutatedDomains),
		OneOrTwoTLDs:    make(map[string]struct{}),
	}

	PublicSuffixListUrl := "https://publicsuffix.org/list/public_suffix_list.dat"
	resp, err := http.Get(PublicSuffixListUrl)
	defer resp.Body.Close()

	if err != nil {
		log.Fatalf("Unable to download PSL list from %s", PublicSuffixListUrl)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "//") {
			continue
		}

		if len(strings.Split(line, ".")) > 2 {
			continue
		}

		wtl.OneOrTwoTLDs[line] = struct{}{}
	}

	for _, domain := range *baseDomains {
		publicSuffix, _ := publicsuffix.PublicSuffix(domain)
		eTLDplus1, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			log.Fatalf("Unable to extract eTLD+1 from %s: %s", domain, err.Error())
		}
		domainNameSansETLD := strings.TrimSuffix(eTLDplus1, "."+publicSuffix)

		for eTLD, _ := range wtl.OneOrTwoTLDs {
			if eTLD != publicSuffix {
				punyDomain, err := idna.ToASCII(domainNameSansETLD + "." + eTLD)
				if err != nil {
					log.Fatalf("Error converting %s to ascii/punycode", domainNameSansETLD+"."+eTLD)
				}
				AddMutation(wtl.WrongTLDDomains, Mutation(punyDomain), domain)
			}
		}
	}

	return wtl
}

func (w *WrongTLDLabeler) LabelDomain(domain string) []DomainLabel {
	domainLabel := make([]DomainLabel, 0)
	mutation := Mutation(domain)

	if _, present := w.WrongTLDDomains[mutation]; present {
		domainLabel = append(domainLabel, WRONGTLD)
	}

	return domainLabel
}

func (w *WrongTLDLabeler) GetMutations() MutatedDomains {
	return w.WrongTLDDomains
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

type PhishTankLabeler struct {
	blacklistedDomains map[string]struct{}
}

func NewPhishTankLabeler() *PhishTankLabeler {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("No caller information")
	}

	file, err := os.Open(filepath.Join(path.Dir(filename), "domainlists/phishtank-hostnames-04-15-2020.txt"))
	if err != nil {
		panic(err)
	}
	defer file.Close()

	ptl := &PhishTankLabeler{
		blacklistedDomains: make(map[string]struct{}),
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		ptl.blacklistedDomains[domain] = struct{}{}
	}

	return ptl
}

func (p *PhishTankLabeler) LabelDomain(domain string) []DomainLabel {
	if _, present := p.blacklistedDomains[domain]; present {
		return []DomainLabel{PHISHTANK}
	}

	return []DomainLabel{}
}

type SafeBrowsingLabeler struct {
	blacklistedDomains map[string]struct{}
}

func NewSafeBrowsingLabeler() *SafeBrowsingLabeler {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("No caller information")
	}

	file, err := os.Open(filepath.Join(path.Dir(filename), "domainlists/gsb_combined_2018-10-29-2020-02-21.txt"))
	if err != nil {
		panic(err)
	}
	defer file.Close()

	ptl := &SafeBrowsingLabeler{
		blacklistedDomains: make(map[string]struct{}),
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		ptl.blacklistedDomains[domain] = struct{}{}
	}

	return ptl
}

func (p *SafeBrowsingLabeler) LabelDomain(domain string) []DomainLabel {
	if _, present := p.blacklistedDomains[domain]; present {
		return []DomainLabel{GOOGLE_SAFEBROWSING}
	}

	return []DomainLabel{}
}
