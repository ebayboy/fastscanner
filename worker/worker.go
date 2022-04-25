package worker

import "log"

type Worker interface {
	Process(interface{}) interface{}
	BlockUntilReady()
	Interrupt()
	Terminate()
}

type WorkRequest struct {
	JobChan       chan<- interface{}
	RetChan       <-chan interface{}
	InterruptFunc func()
}

type WorkerWrapper struct {
	Worker        Worker
	InterruptChan chan struct{}
	ReqChan       chan<- WorkRequest
	CloseChan     chan struct{}
	ClosedChan    chan struct{}
}

func NewWorkerWrapper(reqChan chan<- WorkRequest, worker Worker) *WorkerWrapper {
	w := WorkerWrapper{
		Worker:        worker,
		InterruptChan: make(chan struct{}),
		ReqChan:       reqChan,
		CloseChan:     make(chan struct{}),
		ClosedChan:    make(chan struct{}),
	}

	log.Println("NewWorkerWrapper  before w.Run")
	go w.Run()

	return &w
}

func (w *WorkerWrapper) Interrupt() {
	close(w.InterruptChan)
	w.Worker.Interrupt()
}

func (w *WorkerWrapper) Run() {

	//TODO: jobChan, retChan是内部创建的， 如何写入
	jobChan, retChan := make(chan interface{}), make(chan interface{})

	//Run退出后，关闭通道
	defer func() {
		w.Worker.Terminate()
		close(retChan)
		close(w.ClosedChan)
	}()

	for {
		//BlockUntilReady执行完成后开始处理任务
		w.Worker.BlockUntilReady()

		select {
		//TODO :  case + 初始化
		case w.ReqChan <- WorkRequest{
			JobChan:       jobChan,
			RetChan:       retChan,
			InterruptFunc: w.Interrupt,
		}:
			log.Println("Run Read success: w.ReqChan <- WorkRequest: JobChan")
			select {
			//从jobChan读取到payload
			case payload := <-jobChan:
				log.Println("Run jobChan read payload:", payload)
				//调用Process
				result := w.Worker.Process(payload)
				select {
				//将result写入到retChan
				case retChan <- result:
					log.Println("Run retChan <- result")
					//case + 初始化
				case <-w.InterruptChan:
					w.InterruptChan = make(chan struct{})
					log.Println("Run -w.InterruptChan")
				}
			case <-w.InterruptChan:
				w.InterruptChan = make(chan struct{})
			}
			//从CloseChan读取到消息, 退出Run
		case <-w.CloseChan:
			return
		}
	}
}

func (w *WorkerWrapper) Stop() {
	close(w.CloseChan)
}

func (w *WorkerWrapper) Join() {
	<-w.ClosedChan
}
