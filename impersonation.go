package main

import (
	"errors"
	"github.com/D00MFist/Go4aRun/pkg/winsys"
	"golang.org/x/sys/windows"
	"syscall"
)

func ImpersonateSystem() (*syscall.Token, error) {
	var requiredPrivileges = []string{winsys.SE_DEBUG_NAME, winsys.SE_ASSIGNPRIMARYTOKEN_NAME}
	return ImpersonateUser("S-1-5-18", requiredPrivileges)
}

func ImpersonateLocalService() (*syscall.Token, error) {
	return ImpersonateUser("S-1-5-19", []string{})
}

func ImpersonateUser(sid string, requiredPrivileges []string) (*syscall.Token, error) {
	var hCurrentToken syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(windows.CurrentProcess()), windows.MAXIMUM_ALLOWED, &hCurrentToken); err != nil {
		return nil, LogError(err)
	}
	if !(TokenCheckPrivilege(hCurrentToken, winsys.SE_DEBUG_NAME, true)) {
		return nil, LogError(errors.New("SE_DEBUG privilege could not be enabled"))
	}
	if !(TokenCheckPrivilege(hCurrentToken, winsys.SE_IMPERSONATE_NAME, true)) {
		return nil, LogError(errors.New("SE_IMPERSONATE privilege could not be enabled"))
	}
	hImpersonatedToken, err := FindProcessTokenAndDuplicate(sid, requiredPrivileges)
	if err != nil {
		return nil, LogError(err)
	}
	return hImpersonatedToken, LogError(Impersonate(*hImpersonatedToken))
}

func Impersonate(token syscall.Token) error {
	hCurrentThread := windows.CurrentThread()
	return windows.SetThreadToken(&hCurrentThread, windows.Token(token))
}
