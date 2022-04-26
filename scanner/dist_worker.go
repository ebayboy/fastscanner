package scanner

import (
	"context"
	"math/rand"

	"github.com/Jeffail/tunny"
	log "github.com/sirupsen/logrus"
)

type DistWorkerContext struct {
	Data       interface{} //map[data_key]data
	DistWorker *DistWorker
}

type DistWorker struct {
	NumScanWorker int
	ScanWorkers   []*ScanWorker
	Pool          *tunny.Pool
}

//tunny.pool 多协程同时调用此函数, 要保证线程安全
func selectScanWorker(distWorkerContext interface{}) (res interface{}) {

	ctx := distWorkerContext.(*DistWorkerContext)
	idx := rand.Intn(ctx.DistWorker.NumScanWorker)

	scanCtx := ScanWorkerContext{Data: ctx.Data}
	res = ctx.DistWorker.ScanWorkers[idx].Scan(&scanCtx)

	log.WithFields(log.Fields{"idx:": idx, "ctx": ctx, "res": res}).Info("selectScanWorker")
	return res
}

func NewDistWorker(numScanWorker int, confData []byte, mctx *context.Context, cf *Conf) (*DistWorker, error) {

	dist := &DistWorker{NumScanWorker: numScanWorker}
	dist.Pool = tunny.NewFunc(numScanWorker, selectScanWorker)

	for i := 0; i < numScanWorker; i++ {
		scan_worker, err := NewScanWorker(confData, mctx, cf)
		if err != nil {
			return nil, err
		}
		dist.ScanWorkers = append(dist.ScanWorkers, scan_worker)
	}

	return dist, nil
}

func (w *DistWorker) Process(distWorkerCtx interface{}) (res interface{}) {
	res = w.Pool.Process(distWorkerCtx)
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
