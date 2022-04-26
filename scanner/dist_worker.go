package scanner

import (
	"github.com/fastscanner/worker"
	log "github.com/sirupsen/logrus"
)

//TODO: 使用tunny.tool.ProcessTimeout分发数据到scanWorker
//TODO: scanWorkers

//woker模块， 实现worker.Worker接口
type DistWorker struct {
	ScanWorkers ScanWorker
}

/* Process Flow: payload -> jobChan -> Process -> res -> retChan */
//not call directly, this func is workerWrapper's callback func
func (w *DistWorker) Process(payload interface{}) interface{} {
	// hyperscan match , return result
	res := payload.(string) + ", Process"
	log.Info("====DistWorker reutrn res:", res)
	return res
}

//发送数据到jobChan通道, 读取retChan结果
// http -> jobChan -> hyperscan -> retChan
func (w *DistWorker) ScanPayload(payload interface{}) (res interface{}) {

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

func (w *DistWorker) BlockUntilReady() {
	log.Println("DistWorker BlockUntilReady, WorkerWrappe reqChan:", w.wWraper.ReqChan)
}
func (w *DistWorker) Interrupt() {
	log.Println("DistWorker Interrupt")
}
func (w *DistWorker) Terminate() {
	log.Println("DistWorker Terminate")
}

func NewDistWorker() *DistWorker {
	reqChan := make(chan worker.WorkRequest)
	sWorker := &DistWorker{}
	sWorker.wWraper = worker.NewWorkerWrapper(reqChan, sWorker)

	return sWorker
}

func (w *DistWorker) Stop() {
	log.Info("DistWorkerStop...")
	w.wWraper.Stop()
	log.Info("DistWorker Stoped!")
}

/*
	//TODO: 向jobChan写入数据, 读取retChan结果输出
	go func() {
		log.Info("====Write to w.ReqChan: hello", wWraper.ReqChan)
		res := ScanPayload("hello")
		log.Info("====read from w.ReqChan done!res : res")
	}()
*/
