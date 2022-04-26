package scanner

import (
	"context"
	"math/rand"

	"github.com/Jeffail/tunny"
	log "github.com/sirupsen/logrus"
)

type DistWorkerContext struct {
	Data       interface{}
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

	res = ctx.distWorker.ScanWorkers[idx].Scan(&ctx)

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

//TODO: 此处应该改成通道传递数据进来
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
