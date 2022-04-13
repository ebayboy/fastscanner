package scanner

import (
	"strconv"

	"github.com/flier/gohs/hyperscan"
	log "github.com/sirupsen/logrus"
)

type HSMatcher struct {
	HSDB      hyperscan.BlockDatabase
	HSScratch *hyperscan.Scratch
	Patterns  hyperscan.Patterns
	MZ        string
}

type HSContext struct {
	Data []byte
	Id   uint
	From uint64
	To   uint64
}

func (self *HSMatcher) Output() {
	for _, v := range self.Patterns {
		log.Info("pattern:", v)
	}
}

func onMatch(id uint, from, to uint64, flags uint, context interface{}) error {
	hsctx := context.(*HSContext)
	hsctx.Id = id
	hsctx.From = from
	hsctx.To = to

	return nil
}

func (self *HSMatcher) MatchPool(data interface{}) interface{} {
	//此处使用的scrach应该是clone的
	/*
		ctx := data.(HSContext)

		if err := database.Scan(ctx.Data, scratch, eventHandler, inputData); err != nil {
			log.Error("Error:", err.Error())
		}
	*/

	return nil
}

func (self *HSMatcher) Init() error {

	return nil
}

func NewHSMatcher(rules []Rule, mz string, db hyperscan.BlockDatabase, scratch *hyperscan.Scratch) (*HSMatcher, error) {
	var err error
	matcher := new(HSMatcher)
	matcher.MZ = mz

	for _, rule := range rules {
		//TODO: rule hs_flag ...
		pattern := hyperscan.NewPattern(rule.RX, hyperscan.DotAll|hyperscan.SomLeftMost)
		pattern.Id, err = strconv.Atoi(rule.ID)
		if err != nil {
			log.WithField("rule.Id", rule.ID).Error("Error: strconv.Atoi rule.Id")
			continue
		}
		matcher.Patterns = append(matcher.Patterns, pattern)
	}

	if db == nil {
		matcher.HSDB, err = hyperscan.NewBlockDatabase(matcher.Patterns...)
		if err != nil {
			log.WithField("err", err.Error()).Error("Error: hyperscan.NewBlockDatabase")
			return nil, err
		}
		log.Info("New db:", matcher.HSDB)
	}

	if scratch == nil {
		//alloc
		matcher.HSScratch, err = hyperscan.NewScratch(matcher.HSDB)
		if err != nil {
			log.WithField("err", err.Error()).Error("Error: hyperscan.NewScratch")
			return nil, err
		}
		log.Info("new matcher.HSScratch:", matcher.HSScratch)
	} else {
		//clone
		matcher.HSScratch, err = scratch.Clone()
		if err != nil {
			log.WithField("err", err.Error()).Error("Error: HSScratch.Clone")
			return nil, err
		}
		log.Info("clone matcher:", matcher.HSScratch)
	}

	return matcher, nil
}

func (self *HSMatcher) init() error {
	//TODO: 初始化多个协程，以及通道

	return nil
}

// Test: curl http://localhost:9999/0123456
func (self *HSMatcher) Start() error {

	if err := self.init(); err != nil {
		log.Error("Error", err.Error())
		return err
	}

	//TODO: 轮询监听通道
	//读取请求ctx
	//db.Scan()
	//读取mctx, cancle

	return nil
}

func (self *HSMatcher) Free() error {
	self.HSDB.Close()
	self.HSScratch.Free()

	return nil
}
