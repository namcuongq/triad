package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PAGE_EXECUTE_READWRITE = 0x40
	PROCESS_ALL_ACCESS     = 0x1F0FFF
	CREATE_SUSPENDED       = 0x00000004
)

type ModuleInfo struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func printBanner() {
	banner := `
   _____ _          
  |_   _| |         
    | | | |__   ___ 
    | | | '_ \ / __|
   _| |_| | | | (__ 
  |_____|_| |_|____|
  
  Triad: DLL Unload
  Version: v1.0.0
`
	fmt.Println(banner)
}

func main() {
	printBanner()

	exePath := flag.String("exe", "", "Path to the .exe file")
	dllPattern := flag.String("dll", "", "Substring of the .dll file name to avoid loading")
	flag.Parse()

	if *exePath == "" || *dllPattern == "" {
		fmt.Println("Please provide both the .exe file path and the .dll substring.")
		fmt.Println("Usage: Triad -exe <exe_path> -dll <dll_substring>")
		os.Exit(1)
	}

	if len(*dllPattern) != 3 {
		fmt.Println("Error: The .dll substring must be exactly 3 characters long.")
		os.Exit(1)
	}

	if _, err := os.Stat(*exePath); os.IsNotExist(err) {
		fmt.Printf("The file %s doesn't exist\n", *exePath)
		return
	}

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	cmdLine, _ := syscall.UTF16PtrFromString(*exePath)
	err := syscall.CreateProcess(
		nil,
		cmdLine,
		nil,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		fmt.Printf("Create process error: %v\n", err)
		return
	}
	fmt.Println("Start", exePath, ". PID:", pi.ProcessId)
	fmt.Println("Prevented loading of DLL containing:", *dllPattern)
	fmt.Println("________________________")
	fmt.Println()
	dllHex := stringToHex(*dllPattern)
	sc, _ := hex.DecodeString(fmt.Sprintf("4883F80190909077414D89E94983C1284D8B094981F900F0FF0F722E49FFC149FFC1418039007422418039%s75EE49FFC149FFC1418039%s75E249FFC149FFC1418039%s75D64D31C9C3909090909090909090909090909090909090909090", dllHex[0], dllHex[1], dllHex[2]))
	readAllMemory(sc, pi.Process)
	time.Sleep(3 * time.Second)

	_, err = windows.ResumeThread(windows.Handle(pi.Thread))
	if err != nil {
		fmt.Printf("ResumeThread failed: %v", err)
	}

	syscall.CloseHandle(pi.Process)
	syscall.CloseHandle(pi.Thread)
}

func stringToHex(str string) (result []string) {
	for _, c := range str {
		hex := fmt.Sprintf("%X", c)
		result = append(result, hex)
	}

	return
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func getNTMapViewOfSection() (uintptr, []byte, error) {
	ntdll, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		return 0, nil, fmt.Errorf("LoadLibrary ntdll.dll failed: %v", err)
	}
	defer syscall.FreeLibrary(ntdll)
	NtMapViewOfSectionAddr, err := syscall.GetProcAddress(ntdll, "NtMapViewOfSection")
	if err != nil {
		return 0, nil, fmt.Errorf("GetProcAddress NtMapViewOfSection failed: %v", err)
	}
	opCode := []byte{}
	buffer := make([]byte, 1)
	var bytesRead uintptr
	tmp := NtMapViewOfSectionAddr
	for {
		er := windows.ReadProcessMemory(windows.CurrentProcess(), tmp, &buffer[0],
			1,
			&bytesRead)
		if er != nil {
			return 0, nil, fmt.Errorf("read memory error %v", er)
		}
		opCode = append(opCode, buffer[0])
		if buffer[0] == 0xC3 {
			break
		}
		tmp += 1
	}
	return NtMapViewOfSectionAddr, opCode, nil
}

func readAllMemory(sc []byte, hProcess syscall.Handle) error {
	NTMapViewOfSectionAddr, NTMapViewOfSectionCode, err := getNTMapViewOfSection()
	if err != nil {
		return fmt.Errorf("GetProcAddress NTMapViewOfSection failed: %v", err)
	}

	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		return fmt.Errorf("LoadLibrary kernel32.dll failed: %v", err)
	}
	defer syscall.FreeLibrary(kernel32)

	virtualQueryEx, err := syscall.GetProcAddress(kernel32, "VirtualQueryEx")
	if err != nil {
		return fmt.Errorf("GetProcAddress VirtualQueryEx failed: %v", err)
	}

	var addr uintptr
	var sysCallAddr uintptr
	var caveCallAddr uintptr

	searchBytes := []byte{0x0F, 0x05}
	for {
		var mbi MEMORY_BASIC_INFORMATION
		_, _, err := syscall.Syscall6(
			virtualQueryEx,
			4,
			uintptr(hProcess),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
			0,
			0,
		)
		if err != syscall.Errno(0) {
			if err == windows.ERROR_INVALID_ADDRESS || addr >= 0x7FFFFFFF0000 {
				break
			}
			return fmt.Errorf("VirtualQueryEx failed tại %x: %v", addr, err)
		}

		const MEMORY_STATE_COMMIT = 0x1000
		if mbi.State == MEMORY_STATE_COMMIT {
			regionSize := mbi.RegionSize
			buffer := make([]byte, regionSize)
			var bytesRead uintptr
			windows.ReadProcessMemory(windows.Handle(hProcess), mbi.BaseAddress, &buffer[0],
				regionSize,
				&bytesRead)
			if err != syscall.Errno(0) {
				continue
			}

			for i := 0; i <= int(bytesRead)-len(searchBytes); i++ {
				if bytesEqual(buffer[i:i+len(searchBytes)], searchBytes) {
					sysCallAddr = mbi.BaseAddress + uintptr(i)
					break
				}
			}

			if sysCallAddr != 0 {
				codeCave := bytes.Repeat([]byte{0x00}, len(sc))
				for i := int(NTMapViewOfSectionAddr - mbi.BaseAddress); i <= int(bytesRead)-len(codeCave); i++ {
					if bytesEqual(buffer[i:i+len(codeCave)], codeCave) {
						caveCallAddr = mbi.BaseAddress + uintptr(i)
						break
					}
				}
			}
		}

		if caveCallAddr > NTMapViewOfSectionAddr {
			break
		}

		addr += mbi.RegionSize
	}

	fmt.Printf("NtMapViewOfSection Addr 0x%x\n", NTMapViewOfSectionAddr)
	fmt.Printf("NtMapViewOfSection Code %x\n", NTMapViewOfSectionCode)
	fmt.Printf("Shellcode Addr 0x%x\n", caveCallAddr)
	fmt.Printf("Shellcode %x\n", sc)
	sc = append(sc, NTMapViewOfSectionCode...)
	oldProtect := uint32(0)
	if err = windows.VirtualProtectEx(windows.Handle(hProcess), caveCallAddr, uintptr(len(sc)), windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtectEx %x error: %v\n", unsafe.Pointer(caveCallAddr), err)
	}

	err = windows.WriteProcessMemory(windows.Handle(hProcess), caveCallAddr, &sc[0], uintptr(len(sc)), nil)
	if err != nil {
		return fmt.Errorf("WriteProcessMemory at %v failed: %v", unsafe.Pointer(caveCallAddr), err)
	}
	changeCode := []byte{0xE9}
	changeCode = append(changeCode, uintptrToBytes(caveCallAddr-NTMapViewOfSectionAddr-uintptr(0x5))...)
	changeCode = append(changeCode, 0x00)
	fmt.Printf("Change code 0x%x\n", changeCode)
	if err = windows.VirtualProtectEx(windows.Handle(hProcess), NTMapViewOfSectionAddr, uintptr(len(changeCode)), windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtectEx %v error: %v\n", unsafe.Pointer(NTMapViewOfSectionAddr), err)
	}

	err = windows.WriteProcessMemory(windows.Handle(hProcess), NTMapViewOfSectionAddr, &changeCode[0], uintptr(len(changeCode)), nil)
	if err != nil {
		return fmt.Errorf("WriteProcessMemory at %v failed: %v", unsafe.Pointer(NTMapViewOfSectionAddr), err)
	}

	if err = windows.VirtualProtectEx(windows.Handle(hProcess), NTMapViewOfSectionAddr, uintptr(len(changeCode)), oldProtect, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtectEx %v error: %v\n", unsafe.Pointer(NTMapViewOfSectionAddr), err)
	}

	return nil
}

func uintptrToBytes(ptr uintptr) []byte {
	tempBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		tempBytes[i] = byte(ptr >> (i * 8))
	}

	startIndex := 0
	for startIndex < len(tempBytes) && tempBytes[startIndex] == 0x00 {
		startIndex++
	}

	if startIndex == len(tempBytes) {
		return []byte{}
	}

	return tempBytes[startIndex:]
}
