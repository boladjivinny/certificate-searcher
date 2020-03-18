package main

import (
	"flag"
	"fmt"
	"github.com/pkg/profile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"runtime"
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

// whether the given file or directory exists
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}


// Command line flags
var (
	outputFilepath = flag.String("o", "-", "Output file for certificate")
	workerCount    = flag.Int("workers", runtime.NumCPU(), "Number of parallel parsers/json marshallers")
	memProfile     = flag.Bool("mem-profile", false, "Run memory profiling")
	cpuProfile     = flag.Bool("cpu-profile", false, "Run cpu profiling")
	usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: %s <flags> <input-file-or-dir>\n", os.Args[0], os.Args[0])
		fmt.Print("Flags:\n")
		flag.PrintDefaults()
	}
)

func main() {
	initLogger()

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	inputPath := flag.Arg(0)

	if *cpuProfile {
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	}
	if *memProfile {
		defer profile.Start(profile.MemProfile, profile.ProfilePath("."), profile.NoShutdownHook).Stop()
	}

	if ok, err := exists(inputPath); err != nil || !ok {
		log.Errorf("Invalid input file/directory: %s\n", inputPath)
		if err != nil {
			log.Errorf("%s\n", err.Error())
		}
		os.Exit(1)
	}

	//
	//var filepaths []string
	//
	//if isDir, err := isDirectory(*fname); err != nil {
	//	log.Fatal("Unable to determine if input path is file/directory: ", *fname)
	//} else if isDir {
	//	filepaths, err = mwdomains.GetCertFiles(*fname, *suffix, *recursiveDir)
	//	if err != nil {
	//		log.Fatal("Unable to retrieve files from diretory: ", err)
	//	}
	//} else if !isDir {
	//	filepaths = []string{*fname}
	//}
	//
	//rawCertRecords := make(chan []string, *workerCount)
	//readWG := &sync.WaitGroup{}
	//readWG.Add(1)
	//go readCertificates(filepaths, rawCertRecords, readWG)
	//
	//parsedCertStrings := make(chan string)
	//parsedZlintStrings := make(chan string)
	//
	//workerWG := &sync.WaitGroup{}
	//for i := 0; i < *workerCount; i++ {
	//	workerWG.Add(1)
	//	go certParser(rawCertRecords, parsedCertStrings, parsedZlintStrings, workerWG)
	//}
	//
	//writeWG := &sync.WaitGroup{}
	//writeWG.Add(1)
	//go writeCertificates(parsedCertStrings, writeWG)
	//
	//writeZlintWG := &sync.WaitGroup{}
	//writeZlintWG.Add(1)
	//go writeZlint(parsedZlintStrings, writeZlintWG)
	//
	//readWG.Wait()
	//close(rawCertRecords)
	//workerWG.Wait()
	//close(parsedCertStrings)
	//close(parsedZlintStrings)
	//writeWG.Wait()
	//writeZlintWG.Wait()
}
