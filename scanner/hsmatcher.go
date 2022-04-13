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

// Test: curl http://localhost:9999/0123456
func (self *HSMatcher) Match(ctx *HSContext) error {
	if err := self.HSDB.Scan(ctx.Data, self.HSScratch, onMatch, ctx); err != nil {
		log.WithField("self.HSDB.Scan", err.Error()).Error("hs.scan")
		return err
	}
	//fmt.Printf("Scanning %d bytes %s with Hyperscan Id:%d from:%d to:%d hit:[%s]\n", len(hsctx.Data), hsctx.Data, hsctx.Id, hsctx.From, hsctx.To, hsctx.Data[hsctx.From:hsctx.To])

	return nil
}

func (self *HSMatcher) Free() error {
	self.HSDB.Close()
	self.HSScratch.Free()

	return nil
}
