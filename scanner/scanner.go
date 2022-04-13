package scanner

import (
	"context"
	"encoding/json"

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
	Rules    []Rule   `json:"Rules"`
	Policies []Policy `json:"Policies"`
}

type Conf struct {
	HSConfig HSConfig `json:"HSConfig"`
}

func (self *Scanner) ConfOutput() {
	logrus.Info("ConfOutput")
	logrus.Debug("Conf:", self.Conf)
}

func (self *Scanner) ConfParse(content []byte) error {
	conf := new(Conf)
	if err := json.Unmarshal(content, conf); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Error: json.Unmarshal")
		return err
	}
	self.Conf = conf

	return nil
}

func NewScanner(confData []byte, mctx *context.Context) *Scanner {
	scanner := new(Scanner)
	scanner.Mctx = mctx

	if err := scanner.ConfParse(confData); err != nil {
		logrus.Error("Error: scanner.ConfParse error!")
		return nil
	}

	return scanner
}

func (self *Scanner) Start() {
	//do work
	//tunny goroutine pool process body match
	logrus.Info("Start Scanner done!")

	self.ConfOutput()
}

func (self *Scanner) Stop() {
	logrus.Debug("Stop scanner done!")
}
