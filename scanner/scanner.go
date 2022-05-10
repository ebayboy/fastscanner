package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"
)

//每个scanner包含一组Matchers

/*TODO:
+ 配置解析
+ scanner 包含hs匹配db, scrach/每协程
*/

type ScannerContext struct {
	/* Data : such as uri/request_body/request_uri, type is []byte */
	HSCtx HSContext
	MZ    string
}

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
	HSConfig HSConfig          `json:"hsconfig"`
	RulesMap map[string][]Rule //rules set -> map[mz]rules
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
		log.Info("+New Rule Parse:", rule.MZ)

		MZs := strings.Split(rule.MZ, ",")
		for _, MZ := range MZs {
			_, exist := self.RulesMap[MZ]
			if !exist {
				log.WithField("MZ", MZ).Debug("New MZ:", rule)
				self.RulesMap[MZ] = make([]Rule, 0)
			}
			self.RulesMap[MZ] = append(self.RulesMap[MZ], rule)
			log.WithField("MZ", MZ).Debug("Append rule:", rule)
		}
	}

	for mz, rules := range self.RulesMap {
		log.Info("== MZ:", mz, "   Rules:", rules)
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
	ins.init()

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

func (self *Scanner) Stop() {
	//遍历释放 matcher
	for k, _ := range self.Matchers {
		self.Matchers[k].Stop()
	}
	log.Debug("Stop scanner done!")
}

//ScanWorker -> Scanner
func (self *Scanner) Scan(scannerCtx interface{}) (err error) {

	//选择匹配域对应的matcher， 执行匹配
	//panic: interface conversion: interface {} is *scanner.HSContext, not scanner.ScannerContext
	ctx := scannerCtx.(*ScannerContext)
	matcher, exist := self.Matchers[ctx.MZ]
	if !exist {
		errStr := "Error: matcher not exist:" + ctx.MZ
		log.Error(errStr, " Matchers:", self.Matchers)
		for k, v := range self.Matchers {
			log.Error(k, ":", v)
		}
		return errors.New(errStr)
	}

	if err = matcher.Match(&ctx.HSCtx); err != nil {
		log.Error("Error: matcher.Scan! err:", err.Error())
		return err
	}

	log.WithFields(log.Fields{"ctx": ctx}).Info("Scanner.Scan done!")
	return nil
}
