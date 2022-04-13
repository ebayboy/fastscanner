package scanner

import (
	"context"
	"encoding/json"

	log "github.com/sirupsen/logrus"
)

/*TODO:
+ 配置解析
+ scanner 包含hs匹配db, scrach/每协程
*/

type Scanner struct {
	Mctx     *context.Context
	ConfFile string
	Conf     *Conf
	Matchers map[string]*HSMatcher
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
	Rules    []Rule   `json:"rules"`
	Policies []Policy `json:"policies"`
}

type Conf struct {
	HSConfig HSConfig `json:"hsconfig"`
	RulesMap map[string][]Rule
}

func (self *Conf) ConfOutput() {
	for k, v := range self.RulesMap {
		log.WithFields(log.Fields{"MZ": k, "Rules": v}).Info()
	}
}

func (self *Conf) BuildRules() {

	//将相关匹配域的规则设置到map中
	if self.RulesMap == nil {
		self.RulesMap = make(map[string][]Rule, 0)
	}

	for _, rule := range self.HSConfig.Rules {
		if _, exist := self.RulesMap[rule.MZ]; exist {
			log.WithField("MZ", rule.MZ).Debug("Append rule:", rule)
			self.RulesMap[rule.MZ] = append(self.RulesMap[rule.MZ], rule)
		} else {
			log.WithField("MZ", rule.MZ).Debug("New rule:", rule)
			rules := []Rule{rule}
			self.RulesMap[rule.MZ] = rules
		}
	}
}

func ConfParse(content []byte) (*Conf, error) {
	conf := new(Conf)
	if err := json.Unmarshal(content, conf); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Error: json.Unmarshal")
		return nil, err
	}

	conf.BuildRules()

	conf.ConfOutput()

	return conf, nil
}

func (self *Scanner) Output() {
	log.Info("Matcher count:", len(self.Matchers))
	for k, v := range self.Matchers {
		log.WithField("Matcher", v).Info("Matcher:", k)
	}
}

func NewScanner(confData []byte, mctx *context.Context, cf *Conf) (*Scanner, error) {
	ins := new(Scanner)
	ins.Mctx = mctx

	//解析配置
	if cf == nil {
		conf, err := ConfParse(confData)
		if err != nil {
			log.Error("Error: scanner.ConfParse error!")
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
	if self.Matchers == nil {
		self.Matchers = make(map[string]*HSMatcher, 0)
	}
	for mz, rules := range self.Conf.RulesMap {
		matcher, err := NewHSMatcher(rules, mz, nil, nil)
		if err != nil {
			log.WithField("MZ:", mz).Error("Error: NewHSMatcher")
			continue
		}
		self.Matchers[mz] = matcher
		log.WithField("count", len(self.Matchers)).Info("Add matcher:", matcher.MZ)
	}

	self.Output()
}

func (self *Scanner) Start() {

	//TODO: 初始化通道
	self.init()

	//TODO: 轮询通道
	//TODO: 找到对应Matcher，写入协程对应的写通道

	//do work
	//tunny goroutine pool process body match
	log.Info("Start Scanner done!")
}

func (self *Scanner) Stop() {
	//遍历释放 matcher
	log.Debug("Stop scanner done!")
}

func (self *Scanner) Work(hsctxs []*HSContext) {
}
