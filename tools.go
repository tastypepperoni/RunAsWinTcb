package main

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
)

func CreateCommandLine(randomUid string) string {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return ""
	}
	cmdLine := fmt.Sprintf("%s\\%s %s", systemDirectory, PPLBinary, randomUid)
	return cmdLine
}

func LogStatus(message string, err error, success bool) {
	if success {
		fmt.Println(fmt.Sprintf("[+] %s", message))
		return
	}
	if err != nil {
		fmt.Println(fmt.Sprintf("[-] %s. Error: %s", message, err.Error()))
		return
	}
	fmt.Println(fmt.Sprintf("[-] %s", message))
}

func LogError(err error) error {
	if err == nil {
		return err
	}
	var callerName = "UnknownFunction"
	if info, _, _, ok := runtime.Caller(1); ok {
		details := runtime.FuncForPC(info)
		if details != nil {
			callerName = details.Name()
		}
	}
	callerNameSplit := strings.Split(callerName, ".")
	newErrorText := fmt.Sprintf("%s error: %s", callerNameSplit[len(callerNameSplit)-1], err.Error())
	return errors.New(newErrorText)
}
