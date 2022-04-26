package scanner

import (
	"math/rand"

	"github.com/Jeffail/tunny"
	log "github.com/sirupsen/logrus"
)

type DistWorkerContext struct {
	Payload    interface{}
	distWorker *DistWorker
}

type DistWorker struct {
	NumScanWorker int
	ScanWorkers   []*ScanWorker
	Pool          *tunny.Pool
}

//tunny.pool 多协程同时调用此函数, 要保证线程安全
func selectScanWorker(distWorkerContext interface{}) (res interface{}) {

	ctx := distWorkerContext.(DistWorkerContext)
	idx := rand.Intn(ctx.distWorker.NumScanWorker)
	res = ctx.distWorker.ScanWorkers[idx].ScanPayload(ctx.Payload)

	log.WithFields(log.Fields{"idx:": idx, "ctx": ctx, "res": res}).Info("selectScanWorker")
	return res
}

func NewDistWorker(numScanWorker int) *DistWorker {
	dist := &DistWorker{NumScanWorker: numScanWorker}

	//TODO: scanner -> hsmatcher
	scan_worker := NewScanWorker()
	dist.ScanWorkers = append(dist.ScanWorkers, scan_worker)
	dist.Pool = tunny.NewFunc(numScanWorker, selectScanWorker)

	return dist
}

func (w *DistWorker) Process(payload interface{}) (res interface{}) {
	res = w.Pool.Process(payload)
	return res
}

func (w *DistWorker) Stop() {
	log.Info("DistWorker Stop...")
	if w.Pool != nil {
		w.Pool.Close()
	}
	for k, _ := range w.ScanWorkers {
		w.ScanWorkers[k].Stop()
	}
	log.Info("DistWorker Stoped!")
}
