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

type HSContextResult struct {
	Id   uint   `json:"id"`
	From uint64 `json:"fromi"`
	To   uint64 `json:"to"`
}

type HSContext struct {
	Data    []byte            `json:"data"`
	MZ      string            `json:"match_zone"`
	Results []HSContextResult `json:"rules"`
}

func HSContextsShow(ctxs []HSContext) {
	log.Debug("+++++++++++ HSContextsShow Start+++++++++++++")

	for _, ctx := range ctxs {
		log.WithFields(log.Fields{"\tMZ": ctx.MZ, "Data": string(ctx.Data)}).Debug()
		for _, r := range ctx.Results {
			log.WithFields(log.Fields{"Id": r.Id, "From": r.From, "To": r.To}).Debug()
		}
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
	result := HSContextResult{
		Id:   id,
		From: from,
		To:   to,
	}
	hsctx.Results = append(hsctx.Results, result)
	log.WithFields(log.Fields{"MZ": hsctx.MZ, "Data": hsctx.Data, "id": id, "from": from, "to": to}).Debug("onMatch")

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
	log.WithFields(log.Fields{"ctx.Data": string(ctx.Data), "Results": ctx.Results}).Debug("Match done!")

	return err
}

func (self *HSMatcher) Stop() error {

	self.HSScratch.Free()
	self.HSDB.Close()

	return nil
}
