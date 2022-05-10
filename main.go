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
	"strings"
	"syscall"
	"time"

	"github.com/Jeffail/tunny"
	"github.com/fastscanner/scanner"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

var (
	isdev    bool
	version  bool
	logFile  string
	confFile string
	addr     string
)

func init() {
	//parse flag
	flag.BoolVar(&isdev, "d", false, "run in dev mode")
	flag.BoolVar(&version, "version", false, "output version info")
	flag.StringVar(&logFile, "log", "./logs/fastscanner.log", "error.log")
	flag.StringVar(&confFile, "conf", "./conf/config.json", "config file")
	flag.StringVar(&addr, "addr", ":9999", "TCP address to listen to")
	flag.Parse()

	//log init
	log.SetFormatter(&log.TextFormatter{
		DisableColors:   true,
		TimestampFormat: "1970-00-00 00:00:00",
	})
	if isdev {
		log.SetOutput(os.Stdout)
		log.SetLevel(log.DebugLevel)
	} else {
		logPath := logFile
		rtt_writer, _ := rotatelogs.New(
			logPath+".%Y%m%d%H%M",
			rotatelogs.WithLinkName(logFile),
			rotatelogs.WithMaxAge(72*time.Hour),
			rotatelogs.WithRotationTime(24*time.Hour),
		)

		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
		log.SetOutput(rtt_writer)
		log.SetLevel(log.InfoLevel)
	}

	//set rlimit
	var rLimit syscall.Rlimit
	rLimit.Cur = 65535
	rLimit.Max = 65535
	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Fatal("err:", err.Error())
	}

	//set procs
	runtime.GOMAXPROCS(int(fastScanner.conf.CPUNum))
}

//run in fasthttp goroutine
func request_handler(ctx *fasthttp.RequestCtx) {

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

	distCtx := scanner.DistWorkerContext{DistWorker: distWorker}
	distCtx.Data = make(map[string][]byte)

	if len(ctx.Method()) > 0 {
		distCtx.Data["request_method"] = ctx.Method()
	}
	if len(ctx.RequestURI()) > 0 {
		distCtx.Data["request_uri"] = ctx.RequestURI()
	}
	if len(ctx.Referer()) > 0 {
		distCtx.Data["http_referer"] = ctx.Referer()
	}
	if len(ctx.UserAgent()) > 0 {
		distCtx.Data["http_user_agent"] = ctx.UserAgent()
	}
	if len(ctx.PostBody()) > 0 {
		distCtx.Data["request_body"] = ctx.PostBody()
	}

	res, err := distWorker.Pool.ProcessTimed(&distCtx, time.Second*5)
	if err == tunny.ErrJobTimedOut {
		log.WithFields(log.Fields{"hsCtx": distCtx, "rerr": err.Error()}).Error("Error: Request timed out!")
		return
	}

	log.Debug("======= Request Res Start =======")
	scanner.HSContextsShow(res.([]scanner.HSContext))
	log.Debug("======= Request Res End =======")

	var hit_ids []string
	var hit_payloads []string
	for _, hsctx := range res.([]scanner.HSContext) {
		if hsctx.Id == 0 {
			continue
		}
		rule_id := strconv.Itoa(int(hsctx.Id))
		if err != nil {
			log.Error("Error: strconv.Atoi:", hsctx.Id)
			continue
		}
		hit_ids = append(hit_ids, rule_id)
		hit_payloads = append(hit_payloads, string(hsctx.Data[hsctx.From:hsctx.To]))
	}

	request_id := strconv.FormatUint(ctx.ID(), 10)
	log.WithFields(log.Fields{"hit_ids": hit_ids, "hit_payloads": hit_payloads, "request_id": request_id}).Info("Res")

	if len(hit_ids) > 0 {
		ctx.Response.Header.Set("request-id", request_id)
		ctx.Response.Header.Set("waf-hit-ids", strings.Join(hit_ids, ","))
		ctx.Response.Header.Set("waf-hit-payloads", strings.Join(hit_payloads, ","))
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

type Conf struct {
	Debug   bool   `json:"debug"`
	Version string `json:"version"`
	CPUNum  int    `json:"cpunum"`
	ProcNum int    `json:"procnum"`
}

type FastScanner struct {
	confFile string
	conf     Conf
}

func ServeStart(mctx *context.Context) {

	//start server
	go func() {
		h := request_handler
		if err := fasthttp.ListenAndServe(addr, h); err != nil {
			log.WithField("err", err.Error()).Fatal("Error: fasthttp.ListenAndServe")
		}
	}()

	log.Info("Start server done! Listen on:", addr)

	//exit before main exit
	for {
		select {
		case <-(*mctx).Done():
			log.Debug("Recv mctx Done...")
		default:
			time.Sleep(time.Second)
		}
	}
}

var fastScanner FastScanner
var distWorker *scanner.DistWorker

func main() {

	log.Info("Starting ...")

	//init ctx && signal
	mctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	//read Main Conf
	confData, err := ioutil.ReadFile(confFile)
	if err != nil {
		log.Fatal("Read conf error!")
	}

	if err := json.Unmarshal(confData, &fastScanner.conf); err != nil {
		log.Fatal("Parse main conf error!")
	}
	log.Info("version:", fastScanner.conf.Version)

	distWorker, err = scanner.NewDistWorker(1, confData, &mctx, nil)
	if err != nil {
		log.Fatalln("Error: scanner.NewDistWorker! err:", err.Error())
	}

	go ServeStart(&mctx)

	//============= MODULE ===============

	//wait for exit signal
	<-sigCh

	//module clean

	//main clean
	cancel()
	log.Warn("Stop done!")
}
