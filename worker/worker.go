package worker

type Worker interface {
	Process(interface{}) interface{}
	BlockUntilReady()
	Interrupt()
	Terminate()
}

type WorkRequest struct {
	jobChan       chan<- interface{}
	retChan       <-chan interface{}
	interruptFunc func()
}

type WorkerWrapper struct {
	worker        Worker
	interruptChan chan struct{}
	reqChan       chan<- WorkRequest
	closeChan     chan struct{}
	closedChan    chan struct{}
}

func NewWorkerWrapper(
	reqChan chan<- WorkRequest,
	worker Worker,
) *WorkerWrapper {
	w := WorkerWrapper{
		worker:        worker,
		interruptChan: make(chan struct{}),
		reqChan:       reqChan,
		closeChan:     make(chan struct{}),
		closedChan:    make(chan struct{}),
	}

	go w.Run()

	return &w
}

func (w *WorkerWrapper) Interrupt() {
	close(w.interruptChan)
	w.worker.Interrupt()
}

func (w *WorkerWrapper) Run() {
	jobChan, retChan := make(chan interface{}), make(chan interface{})
	defer func() {
		w.worker.Terminate()
		close(retChan)
		close(w.closedChan)
	}()

	for {
		w.worker.BlockUntilReady()
		select {
		case w.reqChan <- WorkRequest{
			jobChan:       jobChan,
			retChan:       retChan,
			interruptFunc: w.Interrupt,
		}:
			select {
			case payload := <-jobChan:
				result := w.worker.Process(payload)
				select {
				case retChan <- result:
				case <-w.interruptChan:
					w.interruptChan = make(chan struct{})
				}
			case <-w.interruptChan:
				w.interruptChan = make(chan struct{})
			}
		case <-w.closeChan:
			return
		}
	}
}

func (w *WorkerWrapper) Stop() {
	close(w.closeChan)
}

func (w *WorkerWrapper) Join() {
	<-w.closedChan
}
