package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/fastscanner/scanner"
	"github.com/flier/gohs/hyperscan"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

var (
	isdev     bool
	version   bool
	logFile   string
	confFile  string
	addr      string
	compress  bool
	hsMatcher HSMatcher
)

func init() {
	//parse flag
	flag.BoolVar(&isdev, "d", false, "run in dev mode")
	flag.BoolVar(&version, "version", false, "output version info")
	flag.StringVar(&logFile, "log", "./logs/fastscanner.log", "error.log")
	flag.StringVar(&confFile, "conf", "./conf/config.json", "config file")
	flag.StringVar(&addr, "addr", ":9999", "TCP address to listen to")
	flag.BoolVar(&compress, "compress", false, "Whether to enable transparent response compression")
	flag.Parse()

	//log init
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableColors:   true,
		TimestampFormat: "1970-00-00 00:00:00",
	})
	if isdev {
		logrus.SetOutput(os.Stdout)
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logPath := logFile
		rtt_writer, _ := rotatelogs.New(
			logPath+".%Y%m%d%H%M",
			rotatelogs.WithLinkName(logFile),
			rotatelogs.WithMaxAge(72*time.Hour),
			rotatelogs.WithRotationTime(24*time.Hour),
		)

		logrus.SetFormatter(&logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
		logrus.SetOutput(rtt_writer)
		logrus.SetLevel(logrus.InfoLevel)
	}

	//set rlimit
	var rLimit syscall.Rlimit
	rLimit.Cur = 65535
	rLimit.Max = 65535
	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logrus.Fatal("err:", err.Error())
	}

	//set procs
	runtime.GOMAXPROCS(int(fastScanner.conf.CPUNum))

	//hsmatcher init
	hsMatcher.Init()
}
func requestHandler(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, "Hello, world!\n\n")

	fmt.Fprintf(ctx, "Request method is %q\n", ctx.Method())
	fmt.Fprintf(ctx, "RequestURI is %q\n", ctx.RequestURI())
	fmt.Fprintf(ctx, "Requested path is %q\n", ctx.Path())
	fmt.Fprintf(ctx, "Host is %q\n", ctx.Host())
	fmt.Fprintf(ctx, "Query string is %q\n", ctx.QueryArgs())
	fmt.Fprintf(ctx, "User-Agent is %q\n", ctx.UserAgent())
	fmt.Fprintf(ctx, "Connection has been established at %s\n", ctx.ConnTime())
	fmt.Fprintf(ctx, "Request has been started at %s\n", ctx.Time())
	fmt.Fprintf(ctx, "Serial request number for the current connection is %d\n", ctx.ConnRequestNum())
	fmt.Fprintf(ctx, "Your ip is %q\n\n", ctx.RemoteIP())

	fmt.Fprintf(ctx, "Raw request is:\n---CUT---\n%s\n---CUT---", &ctx.Request)

	hsctx := HSContext{Data: ctx.RequestURI()}
	if err := hsMatcher.Match(&hsctx); err != nil {
		logrus.Error("Error:", err.Error())
	}

	if hsctx.Id > 0 {
		ctx.Response.Header.Set("waf-hit-id", strconv.Itoa(int(hsctx.Id)))
		ctx.Response.SetStatusCode(403)
	}

	ctx.SetContentType("text/plain; charset=utf8")

	// Set arbitrary headers
	ctx.Response.Header.Set("X-My-Header", "my-header-value")

	// Set cookies
	var c fasthttp.Cookie
	c.SetKey("cookie-name")
	c.SetValue("cookie-value")
	ctx.Response.Header.SetCookie(&c)
}

func onMatch(id uint, from, to uint64, flags uint, context interface{}) error {
	hsctx := context.(*HSContext)
	hsctx.Id = id
	hsctx.From = from
	hsctx.To = to

	return nil
}

type HSContext struct {
	Data []byte
	Id   uint
	From uint64
	To   uint64
}

type HSMatcher struct {
	HSDB      hyperscan.BlockDatabase
	HSScratch *hyperscan.Scratch
}

type Conf struct {
	Debug   bool   `json:"debug"`
	Version string `json:"version"`
	CPUNum  int    `json:"cpunum"`
}

type FastScanner struct {
	confFile string
	conf     Conf
}

func (self *HSMatcher) Init() (err error) {
	pattern := hyperscan.NewPattern("1234", hyperscan.DotAll|hyperscan.SomLeftMost)
	pattern.Id = 10001

	self.HSDB, err = hyperscan.NewBlockDatabase(pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to compile pattern \"%s\": %s\n", pattern, err.Error())
		return err
	}

	self.HSScratch, err = hyperscan.NewScratch(self.HSDB)
	if err != nil {
		fmt.Fprint(os.Stderr, "ERROR: Unable to allocate scratch space. Exiting.\n")
		return err
	}

	return nil
}

func (self *HSMatcher) Fini() error {

	self.HSDB.Close()
	self.HSScratch.Free()

	return nil
}

// Test: curl http://localhost:9999/0123456
func (self *HSMatcher) Match(ctx *HSContext) error {
	if err := self.HSDB.Scan(ctx.Data, self.HSScratch, onMatch, ctx); err != nil {
		logrus.WithField("self.HSDB.Scan", err.Error()).Error("hs.scan")
		return err
	}
	//fmt.Printf("Scanning %d bytes %s with Hyperscan Id:%d from:%d to:%d hit:[%s]\n", len(hsctx.Data), hsctx.Data, hsctx.Id, hsctx.From, hsctx.To, hsctx.Data[hsctx.From:hsctx.To])

	return nil
}

func module_test(mctx *context.Context) error {

	//start server
	go func() {
		h := requestHandler
		if compress {
			h = fasthttp.CompressHandler(h)
		}

		if err := fasthttp.ListenAndServe(addr, h); err != nil {
			//if err := fasthttp.ListenAndServeUNIX("/tmp/fasthttp_hyperscan.sock", 666, h); err != nil {
			logrus.Fatalf("Error in ListenAndServeUNIX: %v", err)
		}
	}()

	logrus.Info("Start module done!")

	//exit before main exit
	for {
		select {
		case <-(*mctx).Done():
			logrus.Debug("Recv mctx Done...")
			return nil
		default:
			time.Sleep(time.Second)
		}
	}
}

func module_fini() error {
	hsMatcher.Fini()

	logrus.Info("module fini done!")
	return nil
}

var fastScanner FastScanner

func main() {
	logrus.Info("Starting ...")

	//init ctx && signal
	mctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	//read Main Conf
	confData, err := ioutil.ReadFile(confFile)
	if err != nil {
		logrus.Fatal("Read conf error!")
	}

	if err := json.Unmarshal(confData, &fastScanner.conf); err != nil {
		logrus.Fatal("Parse main conf error!")
	}
	logrus.Info("version:", fastScanner.conf.Version)

	//============= MODULE ===============
	//module inti && start
	ins := scanner.NewScanner(confData, &mctx)
	ins.Start()
	logrus.Info("Start module ...!")
	go func() {
		module_test(&mctx)
	}()
	logrus.Info("Start done!")
	//============= MODULE ===============

	//wait for exit signal
	<-sigCh

	//module clean
	module_fini()
	ins.Stop()

	//main clean
	cancel()
	logrus.Warn("Stop done!")
}
