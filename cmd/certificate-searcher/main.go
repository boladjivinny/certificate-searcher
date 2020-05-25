package main

import (
	"bufio"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/pkg/profile"
	cs "github.com/teamnsrg/certificate-searcher"
	"github.com/teamnsrg/zcrypto/x509"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"sync"
)

var log *zap.SugaredLogger

func initLogger() {
	atom := zap.NewAtomicLevelAt(zap.InfoLevel)
	logger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.Lock(os.Stdout),
		atom), zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	defer logger.Sync()
	log = logger.Sugar()
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func verifyPathExists(path string) {
	if ok, err := pathExists(path); err != nil || !ok {
		log.Errorf("Invalid input file/directory: %s\n", path)
		if err != nil {
			log.Errorf("%s\n", err.Error())
		}
		os.Exit(1)
	}
}

func isDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), nil
}

func getDirectoryFiles(dirPath string) ([]string, error) {
	filepaths := make([]string, 0)
	if files, err := ioutil.ReadDir(dirPath); err != nil {
		return filepaths, err
	} else {
		baseDir := strings.TrimSuffix(dirPath, "/")
		for _, info := range files {
			filepaths = append(filepaths, baseDir+"/"+info.Name())
		}
	}

	return filepaths, nil
}

func getFilesForPath(path string) (filepaths []string, err error) {
	if isDir, err := isDirectory(path); err == nil && isDir {
		filepaths, err = getDirectoryFiles(path)
	} else if !isDir {
		filepaths = []string{path}
	}

	return
}

func readCSVFiles(filepaths []string, dataRows chan []string, wg *sync.WaitGroup) {
	for _, filepath := range filepaths {
		log.Infof("reading file %s", filepath)
		f, err := os.Open(filepath)
		if err != nil {
			log.Error(err)
			continue
		}

		reader := csv.NewReader(f)

		var record []string
		for record, err = reader.Read(); err == nil; record, err = reader.Read() {
			sliceCopy := make([]string, len(record))
			copy(sliceCopy, record)
			dataRows <- sliceCopy
		}
		if err != io.EOF {
			log.Error(err)
		}

		f.Close()
	}
	wg.Done()
}

func decodeAndParseChain(encodedCertChain []string, parser *x509.CertParser, onlyParseName bool) ([]*x509.Certificate, error) {
	certChain := make([]*x509.Certificate, 0)
	for _, encodedCert := range encodedCertChain {
		certBytes, err := base64.StdEncoding.DecodeString(encodedCert)
		if err != nil {
			return nil, err
		}

		var cert *x509.Certificate
		if onlyParseName {
			cert, err = cs.ParseCertificateNamesOnly(certBytes)
		} else {
			cert, err = parser.ParseCertificate(certBytes)
		}

		if err != nil {
			log.Errorf("Unable to parse certificate %s due to %s", encodedCert, err)
			return nil, err
		}
		certChain = append(certChain, cert)
	}

	return certChain, nil
}

func extractFeaturesToJSON(chain []*x509.Certificate, labels map[string]cs.LabelsSources) (*cs.LabeledCertChain, error) {
	var leaf, leafParent *x509.Certificate
	if len(chain) == 0 {
		return nil, errors.New("Empty chain")
	}

	leaf = chain[0]
	if len(chain) > 1 {
		leafParent = chain[1]
	}

	certChain := &cs.LabeledCertChain{
		AbuseDomains: labels,
		Leaf:         leaf,
		LeafParent:   leafParent,
		Root:         chain[len(chain)-1],
		ChainDepth:   len(chain),
	}

	return certChain, nil
}

func prettyParseCertificate(encodedCertChain []string, parser *x509.CertParser, labels map[string]cs.LabelsSources) string {
	certChain, err := decodeAndParseChain(encodedCertChain, parser, false)
	processedChain, err := extractFeaturesToJSON(certChain, labels)
	if err != nil {
		log.Error(err)
		return ""
	}

	jsonBytes, err := json.Marshal(processedChain)
	if err != nil {
		log.Error(err)
		return ""
	}

	return string(jsonBytes)
}

func processCertificates(dataRows chan []string, outputStrings chan string, certInfos chan *cs.CertInfo, labelers []cs.DomainLabeler, onlyParseNames bool, statsOnly bool, wg *sync.WaitGroup) {
	const CERT_INDEX int = 1
	const CHAIN_INDEX int = 3
	const CHAIN_DELIMETER string = "|"

	parser := x509.NewCertParser()
	labelers = append(labelers, cs.NewTargetEmbeddingLabeler(&baseDomains))

	for row := range dataRows {
		certB64 := row[CERT_INDEX]
		chainB64 := strings.Split(strings.TrimSpace(row[CHAIN_INDEX]), CHAIN_DELIMETER)

		if row[CHAIN_INDEX] == "" {
			chainB64 = []string{certB64}
		} else if chainB64[0] != certB64 {
			chainB64 = append([]string{certB64}, chainB64...)
		}

		certChain, err := decodeAndParseChain(chainB64, parser, onlyParseNames)
		if err != nil {
			log.Error(err)
			continue
		}

		leafCert := certChain[0]

		if statsOnly {
			if len(certChain) >= 2 {
				parentCert := certChain[1]
				certInfos <- cs.NewCertInfo(leafCert.NotBefore, leafCert.FingerprintNoCT, parentCert.SPKISubjectFingerprint)
			} else {
				certInfos <- cs.NewCertInfo(leafCert.NotBefore, leafCert.FingerprintNoCT, []byte("No parent"))
			}
		} else {
			maldomainLabels := make(map[string]cs.LabelsSources)
			for _, name := range append([]string{leafCert.Subject.CommonName}, leafCert.DNSNames...) {

				for _, labeler := range labelers {
					labels := labeler.LabelDomain(name)
					if len(labels) > 0 {
						if _, present := maldomainLabels[name]; !present {
							maldomainLabels[name] = make(cs.LabelsSources)
						}

						for label, originDomains := range labels {
							maldomainLabels[name][label] = originDomains
						}
					}
				}
			}
			if len(maldomainLabels) > 0 {
				outputStrings <- prettyParseCertificate(chainB64, parser, maldomainLabels)
			}
		}
	}

	wg.Done()
}

func writeOutput(outputStrings chan string, outputFilename string, wg *sync.WaitGroup) {
	var outputFile *os.File
	var err error

	if outputFilename == "-" {
		outputFile = os.Stdout
	} else if len(outputFilename) > 0 {
		outputFile, err = os.Create(outputFilename)
		if err != nil {
			log.Fatal(err)
		}
	}

	w := bufio.NewWriterSize(outputFile, 4096*1000)

	for output := range outputStrings {
		w.WriteString(output + "\n")
	}
	w.Flush()

	outputFile.Close()
	wg.Done()
}

func collectStatistics(certInfos chan *cs.CertInfo, statsFilename string, startValidityFilename string, wg *sync.WaitGroup) {
	var statsFile, startValidityFile *os.File
	var err error

	if startValidityFilename == "-" {
		startValidityFile = os.Stdout
	} else if len(startValidityFilename) > 0 {
		startValidityFile, err = os.Create(startValidityFilename)
		if err != nil {
			log.Fatal(err)
		}
	}

	dateWriter := bufio.NewWriter(startValidityFile)

	certStats := cs.NewCertStats()

	for certInfo := range certInfos {
		if added := certStats.AddParentChild(certInfo.ParentSPKISubject, certInfo.TBSNoCTFingerprint); added {
			dateWriter.WriteString(fmt.Sprintf("%d\n", certInfo.ValidityStart.Unix()))
		}
	}

	dateWriter.Flush()
	startValidityFile.Close()

	if statsFilename == "-" {
		statsFile = os.Stdout
	} else if len(statsFilename) > 0 {
		statsFile, err = os.Create(statsFilename)
		if err != nil {
			log.Fatal(err)
		}
	}

	w := bufio.NewWriter(statsFile)
	w.WriteString(certStats.String())
	w.Flush()
	statsFile.Close()
	wg.Done()
}

// Command line flags
var (
	outputFilepath = flag.String("o", "-", "Output file for certificate")
	statsFilepath  = flag.String("statsFile", "", "Stats file for certificate searching")
	startValidityFilepath  = flag.String("startValidityFile", "", "File for certificate validity start dates")
	workerCount    = flag.Int("workers", runtime.NumCPU(), "Number of parallel parsers/json unmarshallers")
	memProfile     = flag.Bool("mem-profile", false, "Run memory profiling")
	cpuProfile     = flag.Bool("cpu-profile", false, "Run cpu profiling")
	namesOnly      = flag.Bool("names-only", false, "only parse names from cert (faster)")
	domainFilepath = flag.String("domains", "", ".txt file with base domain names for name-similarity labeling")
	usage          = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: %s <flags> <input-file-or-dir>\n", os.Args[0], os.Args[0])
		fmt.Print("Flags:\n")
		flag.PrintDefaults()
	}
)

var baseDomains []string

func main() {
	initLogger()

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	if *cpuProfile {
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	}
	if *memProfile {
		defer profile.Start(profile.MemProfile, profile.ProfilePath("."), profile.NoShutdownHook).Stop()
	}


	defaultDomains := []string{
		"google.com",
		"youtube.com",
		"tmall.com",
		"facebook.com",
		"baidu.com",
		"apple.com",
	}

	if *domainFilepath == "" {
		log.Infof("No base domain file specified, using default list of %d domains", len(defaultDomains))
		baseDomains = defaultDomains
	} else {
		f, err := os.Open(*domainFilepath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		baseDomains = make([]string, 0)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			rawDomain := strings.TrimSpace(scanner.Text())
			sanitizedDomain := strings.ToLower(rawDomain)
			baseDomains = append(baseDomains, sanitizedDomain)

			if rawDomain != sanitizedDomain {
				log.Warnf("domain %s was sanitized to %s", rawDomain, sanitizedDomain)
			}
		}
	}


	statsOnly := *statsFilepath != ""

	inputPath := flag.Arg(0)
	verifyPathExists(inputPath)

	filepaths, err := getFilesForPath(inputPath)
	if err != nil {
		log.Fatalf("Unable to get files for path %s", inputPath)
	}

	log.Info("building domain labelers")

	domainLabelers := []cs.DomainLabeler{
		cs.NewTypoSquattingLabeler(&baseDomains),
		//cs.NewTargetEmbeddingLabeler(&baseDomains), added in each goroutine
		cs.NewHomoGraphLabeler(&baseDomains),
		cs.NewBitSquattingLabeler(&baseDomains),
		cs.NewWrongTLDLabeler(&baseDomains),
		cs.NewPhishTankLabeler(),
		cs.NewSafeBrowsingLabeler(),
	}

	dataRows := make(chan []string, 100)
	readWG := &sync.WaitGroup{}
	readWG.Add(1)
	go readCSVFiles(filepaths, dataRows, readWG)

	certInfos := make(chan *cs.CertInfo, 100)
	outputStrings := make(chan string, 100)
	workerWG := &sync.WaitGroup{}
	for i := 0; i < *workerCount; i++ {
		workerWG.Add(1)

		if statsOnly {
			go processCertificates(dataRows, outputStrings, certInfos, domainLabelers, *namesOnly, statsOnly, workerWG)
		} else {
			go processCertificates(dataRows, outputStrings, nil, domainLabelers, *namesOnly, statsOnly, workerWG)
		}
	}

	statsWG := &sync.WaitGroup{}
	if statsOnly {
		statsWG.Add(1)
		go collectStatistics(certInfos, *statsFilepath, *startValidityFilepath, statsWG)
	}

	writeWG := &sync.WaitGroup{}
	writeWG.Add(1)
	go writeOutput(outputStrings, *outputFilepath, writeWG)

	readWG.Wait()
	close(dataRows)
	workerWG.Wait()
	if statsOnly {
		close(certInfos)
		statsWG.Wait()
	}
	close(outputStrings)
	writeWG.Wait()
}
