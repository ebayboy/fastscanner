package main

import (
	"time"

	"github.com/fastscanner/worker"
	log "github.com/sirupsen/logrus"
)

// -----------------------  implement of worker
func workerCallback(payload interface{}) interface{} {
	log.Println("doWork: payload:", payload)
	return -1
}

//-------------------------
var wWraper *worker.WorkerWrapper
var reqChan chan worker.WorkRequest
var request worker.WorkRequest

//woker模块， 实现worker.Worker接口
type closureWorker struct {
	processor func(interface{}) interface{}
}

func (w *closureWorker) Process(payload interface{}) interface{} {
	log.Info("====closureWorker Process:payload:", payload.(string))
	return payload
}

func SendPayload(payload interface{}) interface{} {

	log.Info("====SendPayload ...")
	//1. read request
	request, open := <-reqChan
	if !open {
		log.Panic("ErrNotRunning")
	}

	//2.1 write payload to jobChan
	request.JobChan <- payload

	//2.2 read payload from retChan
	payload, open = <-request.RetChan
	if !open {
		log.Panic("ErrWorkerClosed")
	}

	return payload
}

func (w *closureWorker) BlockUntilReady() {
	log.Println("closureWorker BlockUntilReady, WorkerWrappe reqChan:", wWraper.ReqChan)
}
func (w *closureWorker) Interrupt() {
	log.Println("closureWorker Interrupt")
}
func (w *closureWorker) Terminate() {
	log.Println("closureWorker Terminate")
}

func Testworker() {

	reqChan = make(chan worker.WorkRequest)

	cWorker := &closureWorker{
		processor: workerCallback,
	}

	wWraper = worker.NewWorkerWrapper(reqChan, cWorker)

	log.Println("worker.NewWorkerWrapper:", wWraper)

	time.Sleep(time.Duration(1) * time.Second)

	log.Println("here should ready done")

	//TODO: 向jobChan写入数据, 读取retChan结果输出

	go func() {
		log.Info("====Write to w.ReqChan:", wWraper.ReqChan)
		SendPayload("hello world")
		log.Info("====Write to w.ReqChan done:", wWraper.ReqChan)
	}()

	time.Sleep(time.Duration(5) * time.Second)

	log.Info("wWraper.Stop...")
	wWraper.Stop()
	log.Info("wWraper.Stop done!")
}
