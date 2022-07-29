package main

import (
	"github.com/hillu/go-ntdll"
	"golang.org/x/sys/windows"
	"syscall"
)

func ObjectManagerCreateDirectory(directoryName string) (*ntdll.Handle, error) {
	var hDirectory ntdll.Handle
	objectAttribute := ntdll.NewObjectAttributes(directoryName, ntdll.OBJ_CASE_INSENSITIVE, 0, nil)
	if err := ntdll.NtCreateDirectoryObject(&hDirectory, ntdll.DIRECTORY_ALL_ACCESS, objectAttribute); err != ntdll.STATUS_SUCCESS {
		return nil, LogError(windows.GetLastError())
	}
	return &hDirectory, nil
}

func ObjectManagerCreateSymlink(linkName string, targetName string) (*ntdll.Handle, error) {
	var hLink ntdll.Handle
	var targetNameUnicode = ntdll.NewUnicodeString(targetName)
	objectAttribute := ntdll.NewObjectAttributes(linkName, ntdll.OBJ_CASE_INSENSITIVE, 0, nil)
	if err := ntdll.NtCreateSymbolicLinkObject(&hLink, ntdll.STANDARD_RIGHTS_ALL, objectAttribute, targetNameUnicode); err != ntdll.STATUS_SUCCESS {
		return nil, LogError(windows.GetLastError())
	}
	return &hLink, nil
}

func MapDll(sectionName string, dllPath string) (*ntdll.Handle, error) {
	var hSection ntdll.Handle
	var dllNtPath windows.NTUnicodeString
	if err := windows.RtlDosPathNameToNtPathName(windows.StringToUTF16Ptr(dllPath), &dllNtPath, nil, nil); err != nil {
		return nil, LogError(err)
	}
	hDllFile, err := syscall.Open(dllNtPath.String(), syscall.O_RDWR, 0)
	if err != nil {
		return nil, LogError(err)
	}
	objectAttribute := ntdll.NewObjectAttributes(sectionName, ntdll.OBJ_CASE_INSENSITIVE, 0, nil)
	if status := ntdll.NtCreateSection(&hSection, ntdll.SECTION_ALL_ACCESS, objectAttribute, nil,
		ntdll.PAGE_READONLY, ntdll.SEC_IMAGE, ntdll.Handle(hDllFile)); status != ntdll.STATUS_SUCCESS {
		return nil, windows.GetLastError()
	}
	return &hSection, nil
}
