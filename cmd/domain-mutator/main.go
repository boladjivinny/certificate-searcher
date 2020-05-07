package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/pkg/profile"
	cs "github.com/teamnsrg/certificate-searcher"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"os"
	"sort"
	"strings"
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

// Command line flags
var (
	outputFilepath = flag.String("o", "-", "Output file for mutated domains")
	workerCount    = flag.Int("workers", 1, "Number of parallel WHOIS requests")
	scanRate       = flag.Int("rate", 10, "Number of WHOIS requests per minute, per worker")
	memProfile     = flag.Bool("mem-profile", false, "Run memory profiling")
	cpuProfile     = flag.Bool("cpu-profile", false, "Run cpu profiling")
	domainFilepath = flag.String("domains", "", ".txt file with base domain names for name-similarity labeling")
	usage          = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: %s <flags>\n", os.Args[0], os.Args[0])
		fmt.Print("Flags:\n")
		flag.PrintDefaults()
	}
)

func main() {
	initLogger()

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	var baseDomains []string
	defaultDomains := []string{
		"www.google.com",
		"www.google.it",
		"www.youtube.com",
		"www.tmall.com",
		"www.facebook.com",
		"www.baidu.com",
		"www.apple.com",
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

	baseDomainMap := make(map[string]struct{})
	for _, domain := range baseDomains {
		baseDomainMap[domain] = struct{}{}
	}

	if *cpuProfile {
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	}
	if *memProfile {
		defer profile.Start(profile.MemProfile, profile.ProfilePath("."), profile.NoShutdownHook).Stop()
	}

	log.Info("building domain labelers")

	domainMutators := []cs.DomainMutator{
		cs.NewTypoSquattingLabeler(&baseDomains),
		cs.NewBitSquattingLabeler(&baseDomains),
		cs.NewWrongTLDLabeler(&baseDomains),
	}

	allMutations := make(cs.MutatedDomains)
	for _, list := range domainMutators {
		for mutation, baseDomains := range list.GetMutations() {
			// remove invalid domains
			if _, err := publicsuffix.EffectiveTLDPlusOne(string(mutation)); err != nil {
				continue
			}
			for domain, _ := range baseDomains {
				cs.AddMutation(allMutations, mutation, domain)
			}
		}
	}

	var outputFile *os.File
	var err error

	if *outputFilepath == "-" {
		outputFile = os.Stdout
	} else if len(*outputFilepath) > 0 {
		outputFile, err = os.Create(*outputFilepath)
		if err != nil {
			log.Fatal(err)
		}
	}

	defer outputFile.Close()

	w := bufio.NewWriter(outputFile)

	for mutation, baseDomains := range allMutations {
		keys := make([]string, 0)
		for domain, _ := range baseDomains {
			keys = append(keys, domain)
		}
		sort.Strings(keys)
		w.WriteString(fmt.Sprintf("%s,%s\n", string(mutation), strings.Join(keys, "|")))
	}
	w.Flush()
}
