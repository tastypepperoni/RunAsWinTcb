package main

import (
	"errors"
	"fmt"
	"github.com/D00MFist/Go4aRun/pkg/winsys"
	"github.com/hillu/go-ntdll"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
)

func FindProcessTokenAndDuplicate(targetSid string, privileges []string) (*syscall.Token, error) {
	systemProcessInfo, err := GetSystemInformation()
	if err != nil {
		return nil, LogError(err)
	}
	for ; ; systemProcessInfo = (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(uintptr(unsafe.Pointer(systemProcessInfo)) + uintptr(systemProcessInfo.NextEntryOffset))) {
		hDuplicateToken, _ := DuplicateProcessToken(systemProcessInfo.UniqueProcessID)
		if hDuplicateToken == nil {
			continue
		}
		newSid, _ := GetTokenSidString(syscall.Token(*hDuplicateToken))
		username, _ := TokenGetUsername(syscall.Token(*hDuplicateToken))
		if newSid == targetSid && username != "" {
			if TokenIsNotRestricted(*hDuplicateToken) {
				if IsTokenPrivileged(*hDuplicateToken, privileges) {
					hDuplicateTokenSys := syscall.Token(*hDuplicateToken)
					return &hDuplicateTokenSys, nil
				}
			}
		}
		if systemProcessInfo.NextEntryOffset == 0 {
			break
		}
	}
	return nil, LogError(errors.New("suitable token could not be found"))
}

func DuplicateProcessToken(processId uintptr) (*windows.Token, error) {
	var hDuplicateToken windows.Token
	var hProcessToken syscall.Token
	hProcess, err := syscall.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(processId))
	if err != nil {
		return nil, LogError(err)
	}
	if err = syscall.OpenProcessToken(hProcess, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &hProcessToken); err != nil {
		return nil, LogError(err)
	}
	if err = windows.DuplicateTokenEx(windows.Token(hProcessToken), windows.MAXIMUM_ALLOWED,
		nil, windows.SecurityImpersonation, windows.TokenImpersonation, &hDuplicateToken); err != nil {
		return nil, LogError(err)
	}
	return &hDuplicateToken, nil
}

func GetSystemInformation() (*windows.SYSTEM_PROCESS_INFORMATION, error) {
	var ErrBufferTooSmall = "The specified information record length does not match the length required for the specified information class."
	var ErrDataTypeMisalignment = "A datatype misalignment was detected in a load or store instruction."
	var bufferSize = uint32(1)
	var requiredSize = uint32(1)
	var systemProcessInfo *windows.SYSTEM_PROCESS_INFORMATION
	for {
		systemProcessInfo = (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&make([]byte, bufferSize)[0]))
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(systemProcessInfo), bufferSize, &requiredSize)
		if err == nil {
			break
		} else if err.Error() != ErrBufferTooSmall && !strings.Contains(err.Error(), ErrDataTypeMisalignment) {
			return nil, LogError(err)
		}
		bufferSize = requiredSize
	}
	return systemProcessInfo, nil
}

func GetTokenSidString(token syscall.Token) (string, error) {
	var sidString string
	sid, err := GetTokenUserInformation(token)
	if err != nil {
		return "", LogError(err)
	}
	sidString, err = sid.String()
	if err != nil {
		return "", LogError(err)
	}
	return sidString, nil
}

func GetTokenUserInformation(token syscall.Token) (*syscall.SID, error) {
	var bufferSize uint32
	var ErrBufferTooSmall = "The data area passed to a system call is too small."
	err := syscall.GetTokenInformation(token, syscall.TokenUser, nil, 0, &bufferSize)
	if !(ErrBufferTooSmall == err.Error()) && err != nil {
		return nil, LogError(err)
	}
	byteBuffer := make([]byte, bufferSize)
	err = syscall.GetTokenInformation(token, syscall.TokenUser, &byteBuffer[0], bufferSize, &bufferSize)
	if err != nil {
		return nil, LogError(err)
	}
	sid := (*syscall.Tokenuser)(unsafe.Pointer(&byteBuffer[0])).User.Sid
	return sid, nil
}

func GetTokenPrivilegeInformation(token windows.Token) (*windows.Tokenprivileges, error) {
	var bufferSize uint32
	var ErrBufferTooSmall = "The data area passed to a system call is too small."
	err := windows.GetTokenInformation(token, syscall.TokenPrivileges, nil, 0, &bufferSize)
	if !(ErrBufferTooSmall == err.Error()) && err != nil {
		return nil, LogError(err)
	}
	byteBuffer := make([]byte, bufferSize)
	err = windows.GetTokenInformation(token, syscall.TokenPrivileges, &byteBuffer[0], bufferSize, &bufferSize)
	if err != nil {
		return nil, LogError(err)
	}
	privilegeInfo := (*windows.Tokenprivileges)(unsafe.Pointer(&byteBuffer[0]))
	return privilegeInfo, nil
}

func GetTokenRestrictionInformation(token windows.Token) (*ntdll.TokenGroupsT, error) {
	var bufferSize uint32
	var ErrBufferTooSmall = "The data area passed to a system call is too small."
	err := windows.GetTokenInformation(token, windows.TokenRestrictedSids, nil, 0, &bufferSize)
	if !(ErrBufferTooSmall == err.Error()) && err != nil {
		return nil, LogError(err)
	}
	byteBuffer := make([]byte, bufferSize)
	err = windows.GetTokenInformation(token, windows.TokenRestrictedSids, &byteBuffer[0], bufferSize, &bufferSize)
	if err != nil {
		return nil, LogError(err)
	}
	restrictionInfo := (*ntdll.TokenGroupsT)(unsafe.Pointer(&byteBuffer[0]))
	return restrictionInfo, nil
}

func TokenCheckPrivilege(token syscall.Token, targetPrivilege string, enablePrivilege bool) bool {
	tokenPrivilegeInfo, err := GetTokenPrivilegeInformation(windows.Token(token))
	if err != nil {
		return false
	}
	for _, eachPrivilege := range tokenPrivilegeInfo.AllPrivileges() {
		privilegeName, _ := winsys.LookupPrivilegeName("", int64(eachPrivilege.Luid.LowPart))
		if strings.ToLower(privilegeName) == strings.ToLower(targetPrivilege) {
			if enablePrivilege {
				var newPrivilegeToken windows.Tokenprivileges
				newPrivilegeToken.PrivilegeCount = 1
				newPrivilegeToken.Privileges[0].Luid = eachPrivilege.Luid
				newPrivilegeToken.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
				if err = windows.AdjustTokenPrivileges(windows.Token(token), false, &newPrivilegeToken, uint32(unsafe.Sizeof(newPrivilegeToken)), nil, nil); err == nil {
					return true
				}
			} else {
				return true
			}
		}
	}
	return false
}

func IsTokenPrivileged(hToken windows.Token, privileges []string) bool {
	for _, eachPrivilege := range privileges {
		if !TokenCheckPrivilege(syscall.Token(hToken), eachPrivilege, false) {
			return false
		}
	}
	return true
}

func TokenGetUsername(token syscall.Token) (string, error) {
	sid, err := GetTokenUserInformation(token)
	if err != nil {
		return "", LogError(err)
	}
	account, domain, _, _ := sid.LookupAccount("")
	return fmt.Sprintf("%s\\%s", domain, account), nil
}

func TokenIsNotRestricted(token windows.Token) bool {
	tokenRestrictionInfo, err := GetTokenRestrictionInformation(token)
	if err != nil {
		return false
	}
	return len(tokenRestrictionInfo.GetGroups()) == 0
}
