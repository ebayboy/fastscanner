package scanner

import (
	"context"
	"errors"

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
	Data interface{} //map[data_key]data
	Res  []HSContext
}

/* Process Flow: payload -> jobChan -> Process -> res -> retChan */
//not call directly, this func is workerWrapper's callback func
func (w *ScanWorker) Process(scanWorkerCtx interface{}) interface{} {

	ctx := scanWorkerCtx.(*ScanWorkerContext)
	log.Info("ScanWorker.Process ctx:", ctx)

	//TODO: forr k, v map , 此处的v是引用吗
	ctxData := ctx.Data.(map[string][]byte)
	for data_key, _ := range ctxData {

		zones, exist := DataZoneMap[data_key]
		if !exist {
			log.WithFields(log.Fields{"data_key": data_key, "DataZoneMap": DataZoneMap}).Error("Error: MZ not exit in DataZoneMap!")
			continue
		}

		for _, zone := range zones.([]string) {

			//TODO: 此处用的data是引用还是复制 ?
			scanCtx := ScannerContext{
				MZ:    zone,
				HSCtx: HSContext{MZ: zone, Data: ctxData[data_key]},
			}
			if err := w.scanner.Scan(&scanCtx); err != nil {
				log.Error("err:", err.Error())
				return err
			}
			ctx.Res = append(ctx.Res, scanCtx.HSCtx)
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
	log.Info("====write to jobChan ... ScanWorkerCtx:", ctx, " w.reqChan:", w.reqChan)

	//将ctx.Data 找到对应的MZ, 输出数据到给scanner, scanner做hyperscan匹配
	//1. wait && read request
	request, open := <-w.reqChan
	if !open {
		log.Error("ErrNotRunning")
		return errors.New("ErrNotRunning")
	}

	log.Info("ScanWorker.Scan get request:", request)
	//2.1 write payload to request.jobChan
	request.JobChan <- ctx

	log.Info("ScanWorker.Scan write to request.JobChan:", request.JobChan)

	//2.2 wait && read payload from request.retChan
	res, open = <-request.RetChan
	if !open {
		log.Panic("ErrWorkerClosed")
		return errors.New("ErrWorkerClosed")
	}
	log.Info("====read from retChan")

	return nil
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

	w := &ScanWorker{}
	w.reqChan = make(chan worker.WorkRequest)
	w.wWraper = worker.NewWorkerWrapper(w.reqChan, w)
	w.scanner, err = NewScanner(confData, mctx, cf)
	if err != nil {
		return nil, err
	}
	log.Info("worker.WorkRequest: ", w, " w.wWraper.ReqChan:", w.wWraper.ReqChan)

	return w, nil
}

func (w *ScanWorker) Stop() {
	log.Info("ScanWorkerStop...")
	w.wWraper.Stop()
	log.Info("ScanWorker Stoped!")
}
