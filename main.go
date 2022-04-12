package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"syscall"

	"github.com/flier/gohs/hyperscan"
	"github.com/valyala/fasthttp"
)

var (
	addr     = flag.String("addr", ":9999", "TCP address to listen to")
	compress = flag.Bool("compress", false, "Whether to enable transparent response compression")
)

func main() {

	//set rlimit
	var rLimit syscall.Rlimit
	rLimit.Cur = 65535
	rLimit.Max = 65535
	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Fatal("err:", err.Error())
	}

	//set procx
	runtime.GOMAXPROCS(4)

	flag.Parse()

	h := requestHandler
	if *compress {
		h = fasthttp.CompressHandler(h)
	}

	if err := fasthttp.ListenAndServe(*addr, h); err != nil {
		//if err := fasthttp.ListenAndServeUNIX("/tmp/fasthttp_hyperscan.sock", 666, h); err != nil {
		log.Fatalf("Error in ListenAndServeUNIX: %v", err)
	}
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

	//TODO: for test
	gohs_test()

	ctx.SetContentType("text/plain; charset=utf8")

	// Set arbitrary headers
	ctx.Response.Header.Set("X-My-Header", "my-header-value")

	// Set cookies
	var c fasthttp.Cookie
	c.SetKey("cookie-name")
	c.SetValue("cookie-value")
	ctx.Response.Header.SetCookie(&c)
}

func on_match(id uint, from, to uint64, flags uint, context interface{}) error {
	inputData := context.([]byte)

	//pattern: 1234
	//from:1 to:5 inputData:0123456

	fmt.Printf("from:%d to:%d inputData:%s match_data:%s\n", from, to, string(inputData), inputData[from:to])
	//fmt.Printf("%s%s%s\n", inputData[start:from], string(inputData[from:to]), inputData[to:end])
	return nil
}

func gohs_test() {
	pattern := hyperscan.NewPattern("1234", hyperscan.DotAll|hyperscan.SomLeftMost)
	database, err := hyperscan.NewBlockDatabase(pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to compile pattern \"%s\": %s\n", pattern, err.Error())
		os.Exit(-1)
	}
	defer database.Close()
	scratch, err := hyperscan.NewScratch(database)
	if err != nil {
		fmt.Fprint(os.Stderr, "ERROR: Unable to allocate scratch space. Exiting.\n")
		os.Exit(-1)
	}
	defer scratch.Free()

	inputData := []byte("0123456")
	fmt.Printf("Scanning %d bytes with Hyperscan\n", len(inputData))
	if err := database.Scan(inputData, scratch, on_match, inputData); err != nil {
		fmt.Fprint(os.Stderr, "ERROR: Unable to scan input buffer. Exiting.\n")
		os.Exit(-1)
	}

	return
}
