package common

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
)

func GetProcDir() (string, error) {
	var procDir string

	exDir, err := os.Executable()
	if err != nil {
		logrus.Error("Error: get procDir!!! err:", err.Error())
		return procDir, errors.New("Error: get procDir!!!")
	}

	dir := filepath.Dir(exDir)                //  .../bin/riskstat
	dir = strings.Replace(dir, "\\", "/", -1) // ...
	procDir = dir[0:strings.LastIndex(dir, "/")]

	return procDir, nil
}

func PidfileExit(pidfile string) (once_pid int, started bool) {

	//打开pid文件
	pf, err := os.OpenFile(pidfile, os.O_RDWR, 0)
	defer pf.Close()

	if os.IsNotExist(err) {
		//错误1: 如果pid文件不存在
		started = false
	} else if err != nil {
		//其他错误
		fmt.Printf("pidfile check error:%v\n", err)
		return
	} else {
		//pid文件存在
		pd, _ := ioutil.ReadAll(pf)
		old_pid, err := strconv.Atoi(string(pd))
		if err == nil {
			//pid 存在，直接返回
			// not os.FindProcess(), Unix?
			err := syscall.Kill(old_pid, 0) //发送信号0， 验证进程是否存在
			if err == nil {
				started = true
				once_pid = old_pid
			}
		} else {
			//pid进程号错误,不是数字
			fmt.Println("pid ProcNum error:", err.Error())
			return
		}
	}

	if !started {
		//如果pid文件不存在， 创建文件
		pf, err := os.Create(pidfile)
		defer pf.Close()
		if err != nil {
			fmt.Println("create pid file error.")
			return
		}
		new_pid := os.Getpid()
		n, err := pf.Write([]byte(fmt.Sprintf("%d", new_pid)))
		if err != nil {
			fmt.Println("write pid failed.")
		} else {
			once_pid = new_pid
			fmt.Println("write pid ok success! pidfile:", pidfile, " pid:", once_pid, " size:", n)
		}
	}

	return
}

func HandleSingle() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGSTOP, syscall.SIGHUP)
	<-sigs
	fmt.Println("graceful exit...")
}
