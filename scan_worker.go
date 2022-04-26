package main

import (
	"github.com/fastscanner/worker"
	log "github.com/sirupsen/logrus"
)

/*
TODO:
+ 每个woker对应一个matcher
*/

//woker模块， 实现worker.Worker接口
type ScanWorker struct {
	wWraper *worker.WorkerWrapper
	reqChan chan worker.WorkRequest
	request worker.WorkRequest
}

/* Process Flow: payload -> jobChan -> Process -> res -> retChan */
//not call directly, this func is workerWrapper's callback func
func (w *ScanWorker) Process(payload interface{}) interface{} {
	// hyperscan match , return result
	res := payload.(string) + ", Process"
	log.Info("====ScanWorker reutrn res:", res)
	return res
}

//发送数据到jobChan通道, 读取retChan结果
// http -> jobChan -> hyperscan -> retChan
func (w *ScanWorker) ScanPayload(payload interface{}) (res interface{}) {

	log.Info("====write to jobChan ...")
	//1. read request
	request, open := <-w.reqChan
	if !open {
		log.Panic("ErrNotRunning")
	}

	//2.1 write payload to request.jobChan
	request.JobChan <- payload

	//2.2 read payload from request.retChan
	res, open = <-request.RetChan
	if !open {
		log.Panic("ErrWorkerClosed")
	}
	log.Info("====read from retChan")

	return res
}

func (w *ScanWorker) BlockUntilReady() {
	log.Println("ScanWorker BlockUntilReady, WorkerWrappe reqChan:", w.wWraper.ReqChan)
}
func (w *ScanWorker) Interrupt() {
	log.Println("ScanWorker Interrupt")
}
func (w *ScanWorker) Terminate() {
	log.Println("ScanWorker Terminate")
}

func NewScanWorker() *ScanWorker {
	reqChan := make(chan worker.WorkRequest)
	sWorker := &ScanWorker{}
	sWorker.wWraper = worker.NewWorkerWrapper(reqChan, sWorker)

	return sWorker
}

func (w *ScanWorker) Stop() {
	log.Info("ScanWorkerStop...")
	w.wWraper.Stop()
	log.Info("ScanWorker Stoped!")
}

/*
	//TODO: 向jobChan写入数据, 读取retChan结果输出
	go func() {
		log.Info("====Write to w.ReqChan: hello", wWraper.ReqChan)
		res := ScanPayload("hello")
		log.Info("====read from w.ReqChan done!res : res")
	}()
*/
