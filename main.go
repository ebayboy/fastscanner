package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

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
	flag.StringVar(&logFile, "log", "./logs/error.log", "error.log")
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
		logrus.SetReportCaller(true)
		logrus.SetOutput(os.Stdout)
		logrus.SetLevel(logrus.DebugLevel)
		return
	}

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

	//set rlimit
	var rLimit syscall.Rlimit
	rLimit.Cur = 65535
	rLimit.Max = 65535
	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logrus.Fatal("err:", err.Error())
	}

	//set procs
	runtime.GOMAXPROCS(4)

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

	hsMatcher.Match(&hsctx)
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
func (self *HSMatcher) Match(ctx *HSContext) (err error) {
	err = self.HSDB.Scan(ctx.Data, self.HSScratch, onMatch, ctx)
	if err != nil {
		fmt.Fprint(os.Stderr, "ERROR: Unable to scan input buffer. Exiting.\n")
		return err
	}
	//fmt.Printf("Scanning %d bytes %s with Hyperscan Id:%d from:%d to:%d hit:[%s]\n", len(hsctx.Data), hsctx.Data, hsctx.Id, hsctx.From, hsctx.To, hsctx.Data[hsctx.From:hsctx.To])

	return nil
}

func module_test(mctx *context.Context) error {

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

	logrus.Info("Start done!")
	return nil
}

func module_fini() error {
	hsMatcher.Fini()

	logrus.Info("module fini done!")
	return nil
}

func main() {
	logrus.Info("Starting ...")

	//init ctx && signal
	mctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	//module inti && start
	module_test(&mctx)

	//wait for exit signal
	<-sigCh

	//module clean
	module_fini()

	//main clean
	cancel()
	time.Sleep(time.Second * 1)
	logrus.Warn("Stop spider_ip_rdns done!")
}
