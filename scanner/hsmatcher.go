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
	Data []byte //input
	MZ   string //input
	Id   uint   //output
	From uint64 //output
	To   uint64 //output
}

func HSContextsShow(ctxs []HSContext) {
	log.Debug("+++++++++++ HSContextsShow Start+++++++++++++")
	for _, ctx := range ctxs {
		log.WithFields(log.Fields{"MZ": ctx.MZ, "Data": string(ctx.Data), "Id": ctx.Id, "From": ctx.From, "To": ctx.To}).Debug("")
	}
	log.Debug("+++++++++++ HSContextsShow End+++++++++++++")
}

func (self *HSMatcher) Output() {
	for _, v := range self.Patterns {
		log.Debug("pattern:", v)
	}
}

func onMatch(id uint, from, to uint64, flags uint, context interface{}) error {

	hsctx := context.(*HSContext)
	hsctx.Id = id
	hsctx.From = from
	hsctx.To = to

	log.WithFields(log.Fields{"MZ": hsctx.MZ, "Data": hsctx.Data, "id": hsctx.Id, "from": hsctx.From, "to": hsctx.To}).Debug("onMatch")

	return nil
}

func NewHSMatcher(rules []Rule, mz string, db hyperscan.BlockDatabase, scratch *hyperscan.Scratch) (*HSMatcher, error) {
	var err error
	matcher := new(HSMatcher)
	matcher.MZ = mz

	log.Debug("NewHSMatcher rules:", rules)

	for _, rule := range rules {
		//TODO: rule hs_flag ...
		pattern := hyperscan.NewPattern(rule.RX, hyperscan.DotAll|hyperscan.SomLeftMost)
		pattern.Id, err = strconv.Atoi(rule.ID)
		if err != nil {
			log.WithField("rule", rule).Error("Error: strconv.Atoi rule.Id")
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
		log.Debug("New db:", matcher.HSDB)
	}

	if scratch == nil {
		//alloc
		matcher.HSScratch, err = hyperscan.NewScratch(matcher.HSDB)
		if err != nil {
			log.WithField("err", err.Error()).Error("Error: hyperscan.NewScratch")
			return nil, err
		}
		log.Debug("new matcher.HSScratch:", matcher.HSScratch)
	} else {
		//clone
		matcher.HSScratch, err = scratch.Clone()
		if err != nil {
			log.WithField("err", err.Error()).Error("Error: HSScratch.Clone")
			return nil, err
		}
		log.Debug("clone matcher:", matcher.HSScratch)
	}

	return matcher, nil
}

func (self *HSMatcher) Match(HSCtx interface{}) (err error) {
	ctx := HSCtx.(*HSContext)

	if err = self.HSDB.Scan(ctx.Data, self.HSScratch, onMatch, ctx); err != nil {
		log.WithFields(log.Fields{"err": err.Error(), "ctx": ctx}).Error("ERROR: Unable to scan input buffer. Exiting.")
		return err
	}
	log.WithFields(log.Fields{"ctx.Data": string(ctx.Data), "Id": ctx.Id, "MZ": ctx.MZ}).Debug("Match done!")

	return err
}

func (self *HSMatcher) Stop() error {

	self.HSScratch.Free()
	self.HSDB.Close()

	return nil
}
