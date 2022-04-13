package scanner

import (
	"context"
	"encoding/json"

	"github.com/flier/gohs/hyperscan"
	"github.com/sirupsen/logrus"
)

/*TODO:
+ 配置解析
+ scanner 包含hs匹配db, scrach/每协程
*/

type Scanner struct {
	Mctx     *context.Context
	ConfFile string
	Conf     *Conf
	Db       hyperscan.BlockDatabase
	Scratch  *hyperscan.Scratch
	Matchers []*HSMatcher
}

type Rule struct {
	ID       string `json:"id"`
	MZ       string `json:"mz"`
	RX       string `json:"rx"`
	RuleType string `json:"rule_type"`
	HSFlag   string `json:"hs_flag"`
}

type Policy struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
	Action string `json:"action"`
}

type HSConfig struct {
	ProcNum  int      `json:"procnum"`
	Rules    []Rule   `json:"rules"`
	Policies []Policy `json:"policies"`
}

type Conf struct {
	HSConfig HSConfig `json:"hsconfig"`
}

func (self *Scanner) ConfOutput() {
	logrus.Info("ConfOutput")
	logrus.Debug("Conf:", self.Conf)
}

func ConfParse(content []byte) (*Conf, error) {
	conf := new(Conf)
	if err := json.Unmarshal(content, conf); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Error: json.Unmarshal")
		return nil, err
	}

	return conf, nil
}

func NewScanner(confData []byte, mctx *context.Context, cf *Conf) (*Scanner, error) {
	ins := new(Scanner)
	ins.Mctx = mctx

	//解析配置
	if cf == nil {
		conf, err := ConfParse(confData)
		if err != nil {
			logrus.Error("Error: scanner.ConfParse error!")
			return nil, err
		}
		ins.Conf = conf
	} else {
		ins.Conf = cf
	}

	//初始化matchers

	return ins, nil
}

func (self *Scanner) init() {
	for i := 0; i < self.Conf.HSConfig.ProcNum; i++ {
		if matcher, err := NewHSMatcher(self.Conf.HSConfig.Rules, self.Db, self.Scratch); err != nil {
			logrus.WithField("idx:", i).Error("Error: NewHSMatcher")
			continue
		} else {
			if self.Db == nil {
				self.Db = matcher.HSDB
			}
			if self.Scratch == nil {
				self.Scratch = matcher.HSScratch
			}
			logrus.WithField("idx", i).Info("init matcher ok!")
		}
	}
}

func (self *Scanner) Start() {

	self.init()

	//do work
	//tunny goroutine pool process body match
	logrus.Info("Start Scanner done!")

	self.ConfOutput()
}

func (self *Scanner) Stop() {
	//遍历释放 matcher
	logrus.Debug("Stop scanner done!")
}
