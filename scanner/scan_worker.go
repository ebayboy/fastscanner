package scanner

import (
	"context"

	"github.com/fastscanner/worker"
	log "github.com/sirupsen/logrus"
)

/*
TODO:
+ 每个scan_woker对应一个scanner
+ 每个scanner对应一组matcher
*/

// scanWorker 封装 hsmatchers

//woker模块， 实现worker.Worker接口
type ScanWorker struct {
	wWraper *worker.WorkerWrapper
	reqChan chan worker.WorkRequest
	request worker.WorkRequest
	scanner *Scanner
}

type ScanWorkerContext struct {
	Data map[string]interface{} //map[data_key]data
	Res  []HSContext
}

/* Process Flow: payload -> jobChan -> Process -> res -> retChan */
//not call directly, this func is workerWrapper's callback func
func (w *ScanWorker) Process(scanWorkerCtx interface{}) interface{} {

	ctx := scanWorkerCtx.(*ScanWorkerContext)
	log.Info("ScanWorker.Process ctx:", ctx)

	//forr k, v map , 此处的v是引用吗
	for data_key, _ := range ctx.Data {
		zones, exist := DataZoneMap[data_key]
		if !exist {
			log.WithFields(log.Fields{"data_key": data_key, "DataZoneMap": DataZoneMap}).Error("Error: MZ not exit!")
			continue
		}

		for _, zone := range zones.([]string) {
			//TODO: 此处用的data是引用还是复制 ?
			hsctx := HSContext{MZ: zone, Data: ctx.Data[data_key].([]byte)}
			if err := w.scanner.Scan(&hsctx); err != nil {
				log.Error("err:", err.Error())
				return err
			}
			ctx.Res = append(ctx.Res, hsctx)
		}
	}

	log.Info("ScanWorker.Process Res:", ctx.Res)

	return nil
}

//发送数据到jobChan通道, 读取retChan结果
// http -> jobChan -> hyperscan -> retChan
// distWoker -> scanWorker -> scanner -> hyperscan
//TODO: 此处会block
//TODO: 多协程同时调用会不会数据与输出结果混淆
func (w *ScanWorker) Scan(scanWorkerCtx interface{}) (res interface{}) {

	ctx := scanWorkerCtx.(*ScanWorkerContext)
	log.Info("====write to jobChan ... ScanWorkerCtx:", ctx)

	//将ctx.Data 找到对应的MZ, 输出数据到给scanner, scanner做hyperscan匹配

	//1. wait && read request
	request, open := <-w.reqChan
	if !open {
		log.Error("ErrNotRunning")
	}

	//2.1 write payload to request.jobChan
	request.JobChan <- ctx

	//2.2 wait && read payload from request.retChan
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

func NewScanWorker(confData []byte, mctx *context.Context, cf *Conf) (*ScanWorker, error) {
	var err error
	reqChan := make(chan worker.WorkRequest)
	w := &ScanWorker{}
	w.wWraper = worker.NewWorkerWrapper(reqChan, w)
	w.scanner, err = NewScanner(confData, mctx, cf)
	if err != nil {
		return nil, err
	}

	return w, nil
}

func (w *ScanWorker) Stop() {
	log.Info("ScanWorkerStop...")
	w.wWraper.Stop()
	log.Info("ScanWorker Stoped!")
}
