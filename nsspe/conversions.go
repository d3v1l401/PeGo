package nsspe

type SecCharacteristics struct {
	// Abandoned / reserved
	TypeRegistry  bool
	Dissect       bool
	DoNotLoad     bool
	GroupSection  bool
	NoPadding     bool
	CopyOfSection bool
	// accessible
	ContainsCode              bool
	ContainsInitializedData   bool
	ContainsUninitializedData bool
	ContainsLinkedInfo        bool
	LinkerInfo                bool
	ContainsFarData           bool
	RequiresSystemHeap        bool
	CanBeMemoryPurged         bool
	Has16Data                 bool
	IsLocked                  bool
	MustBePreloaded           bool
	NoCacheAllowed            bool
	NoPagingAllowed           bool
	IsShared                  bool
	// Most importants!
	Executable bool
	Readable   bool
	Writeable  bool
}

type DllSecCharacteristics struct {
	CallOnDLLInit    bool
	CallOnDLLTerm    bool
	CallOnThreadInit bool
	CallOnThreadTerm bool

	IsLargeAddress       bool
	ASLREnabled          bool
	CodeIntegrityEnabled bool
	DEPEnabled           bool
	IsolationEnabled     bool
	SEHEnabled           bool
	BoundEnabled         bool
	WDMFile              bool
	FlowGuardEnabled     bool
}

// Directory offset - pointing section Virtual Address - pointing section Raw Address
func PtrToRVA(rva, va, offset uint64) int64 {
	rawPointer := int64(rva - va - offset)
	if rawPointer < 0 {
		rawPointer = rawPointer * -1
	}
	return rawPointer
}

func PtrToRVA2(sections []SectionHeader, rva uint64) (*SectionHeader, int64) {
	var section *SectionHeader
	var offset int64
	for i := range sections {
		section = &sections[i]
		if (uint64(section.VirtualAddress) <= rva) && (rva < uint64(section.VirtualAddress+section.VirtualSize)) {
			offset = int64(rva - uint64(section.VirtualAddress))
			break
		}
	}

	return section, offset
}

func RvaToRawAddr(section SectionHeader, rva int64) int64 {
	return int64(int64(section.PointerToRawData) + rva)
}

func GibMeOffset(sections []SectionHeader, rva uint64) int64 {
	sect, rvaa := PtrToRVA2(sections, rva)
	return RvaToRawAddr(*sect, rvaa)
}

func DecodeCOFFCharacts(characts uint16) *COFFCharacteristics {
	var chars COFFCharacteristics
	shift := ImageCharacteristics(characts)

	if (shift & IMAGE_FILE_EXECUTABLE_IMAGE) != 0 {
		chars.IsExecutable = true
	}
	if (shift & IMAGE_FILE_32BIT_MACHINE) != 0 {
		chars.Is32BitMachine = true
	}
	if (shift & IMAGE_FILE_AGGRESIVE_WS_TRIM) != 0 {
		chars.AggressiveTrimWorkSet = true
	}
	if (shift & IMAGE_FILE_RELOCS_STRIPPED) != 0 {
		chars.RelocationStripped = true
	}
	if (shift & IMAGE_FILE_LINE_NUMS_STRIPPED) != 0 {
		chars.LineNumbersStripped = true
	}
	if (shift & IMAGE_FILE_LOCAL_SYMS_STRIPPED) != 0 {
		chars.LineNumbersStripped = true
	}
	if (shift & IMAGE_FILE_LOCAL_SYMS_STRIPPED) != 0 {
		chars.LocalSymbolsStripped = true
	}
	if (shift & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0 {
		chars.CanHandleLargeAddressSpace = true
	}
	if (shift & IMAGE_FILE_16BIT_MACHINE) != 0 {
		chars.Is16BitMachine = true
	}
	if (shift & IMAGE_FILE_BYTES_REVERSED_LO) != 0 {
		chars.ReversedByteOrderLow = true
	}
	if (shift & IMAGE_FILE_BYTES_REVERSED_HI) != 0 {
		chars.ReservedByteOrderHigh = true
	}
	if (shift & IMAGE_FILE_DEBUG_STRIPPED) != 0 {
		chars.DebugInfoStrippedFromDBG = true
	}
	if (shift & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) != 0 {
		chars.RunFromSwapIfOnUSB = true
	}
	if (shift & IMAGE_FILE_NET_RUN_FROM_SWAP) != 0 {
		chars.RunFromSwapIfOnline = true
	}
	if (shift & IMAGE_FILE_SYSTEM) != 0 {
		chars.IsSystemFile = true
	}
	if (shift & IMAGE_FILE_DLL) != 0 {
		chars.IsDLL = true
	}
	if (shift & IMAGE_FILE_UP_SYSTEM_ONLY) != 0 {
		chars.OnlyUPMachine = true
	}

	return &chars
}

func DecodeDllCharacts(characts uint16) *DllSecCharacteristics {
	shift := DllCharacteristics(characts)
	var chars DllSecCharacteristics

	if shift&IMAGE_LIBRARY_PROCESS_INIT != 0 {
		chars.CallOnDLLInit = true
	}
	if shift&IMAGE_LIBRARY_PROCESS_TERM != 0 {
		chars.CallOnDLLTerm = true
	}
	if shift&IMAGE_LIBRARY_THREAD_INIT != 0 {
		chars.CallOnThreadInit = true
	}
	if shift&IMAGE_LIBRARY_THREAD_TERM != 0 {
		chars.CallOnThreadTerm = true
	}
	if shift&IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 {
		// Another indicator of 64bit addressing.
	}
	if shift&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
		chars.ASLREnabled = true
	}
	if shift&IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0 {
		chars.CodeIntegrityEnabled = true
	}
	if shift&IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
		// NX Compatible...what is an NX?
	}
	if shift&IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
		chars.SEHEnabled = false
	}
	if shift&IMAGE_DLLCHARACTERISTICS_NO_BIND != 0 {
		chars.BoundEnabled = false
	}
	if shift&IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0 {
		// Should not be executed in an AppContainer
	}
	if shift&IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0 {
		chars.WDMFile = true
	}
	if shift&IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
		chars.FlowGuardEnabled = true
	}
	if shift&IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE != 0 {
		// Never found out.
	}

	return &chars
}

func DecodeCharacts(section SectionHeader) *SecCharacteristics {
	// Windows sectioning is quite strict on a few things, most of them are useless now or only used by drivers
	// But in the common context, PE files have 5 fundamental flags: writable, readable, executables and if contains initialized/uninit. data.
	//
	// To make an example: a .text section (compiled bytecode) is executable, readable AND WRITABLE means the code is self modifying which is typical
	// from a packer or a self-injecting malware (with encrypted shellcode somewhere).
	// If a memory area is non-writable and something is writing on it, it will throw an exception and crash.
	// This can be bypassed with VirtualProtect on runtime.
	var shift uint = uint(section.Characteristics)
	var chars SecCharacteristics
	if shift&uint(IMAGE_SCN_MEM_EXECUTE) > 0 {
		chars.Executable = true
	}
	if shift&uint(IMAGE_SCN_MEM_READ) > 0 {
		chars.Readable = true
	}
	if shift&uint(IMAGE_SCN_MEM_WRITE) > 0 {
		chars.Writeable = true
	}
	return &chars
}

func GetPointingSection(sections []SectionHeader, pointer uint64) *SectionHeader {
	for v := range sections {
		if pointer >= uint64(sections[v].VirtualAddress) && pointer <= uint64(sections[v].VirtualAddress+sections[v].VirtualSize) {
			return &sections[v]
		}
	}
	return nil
}

func DirEntryNameToType(name uint16) string {
	switch name {
	case DIRECTORY_TYPE_CONFIGURATION_FILES:
		return "ConfigurationFiles"
	case DIRECTORY_TYPE_ICONS:
		return "Icons"
	case DIRECTORY_TYPE_VERSION_INFO:
		return "Versioning"
	case DIRECTORY_TYPE_ICON_GROUPS:
		return "IconGroups"
	default:
		return "Unknown"
	}
}
