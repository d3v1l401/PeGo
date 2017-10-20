package nsspe

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"./shannon"
	"github.com/michielbuddingh/spamsum"
)

type Parsed struct {
	PeFile   *PE
	data     []byte
	Path     string
	signDb   *SignatureDatabase
	scantype string
	ordMap   map[string]lib
}

func (p *Parsed) decryptRich(buffer []byte) []byte {
	if uint(len(buffer)) < THIS_SIZE_OF_RICH {
		return nil
	}
	buffOut := make([]byte, THIS_SIZE_OF_RICH)
	key := make([]byte, 4)
	binary.BigEndian.PutUint32(key, IMAGE_DANS_SIGNATURE)
	keyidx := 0

	for index := 0; index < len(buffer); index++ {
		buffOut[index] = buffer[index] ^ key[keyidx]

		if keyidx == 3 {
			keyidx = 0
		} else {
			keyidx++
		}
	}

	return buffOut
}

func (p *Parsed) parseDOS(reader *bytes.Reader) error {
	if reader.Len() < MINIMUM_PE_SIZE {
		return errors.New("PE is too small.")
	}
	p.setPointer(reader, 0)

	p.PeFile = new(PE)

	if err := binary.Read(reader, binary.LittleEndian, &p.PeFile.DosHeader); err != nil {
		return err
	}

	if p.PeFile.DosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return errors.New("File is not a PE.")
	}

	return nil
}

func (p *Parsed) setPointer(handler *bytes.Reader, loc uint64) {
	handler.Seek(int64(loc), os.SEEK_SET)
}

func (p *Parsed) parseRich(reader *bytes.Reader) error {
	p.setPointer(reader, SIZE_OF_DOSH+SIZE_OF_DOSI)

	THIS_SIZE_OF_RICH = uint((p.PeFile.DosHeader.E_lfanew) - uint32(SIZE_OF_DOSH+SIZE_OF_DOSI))
	// Rich header might not be present in some very old samples, let's read it only if it's ok and exists.
	// Reading it influences the alignment of the next header.
	if THIS_SIZE_OF_RICH > MIN_SIZE_OF_RICH && THIS_SIZE_OF_RICH < 0x200 {
		buff := make([]byte, THIS_SIZE_OF_RICH)
		if err := binary.Read(reader, binary.BigEndian, &buff); err != nil {
			return err
		}

		r2 := bytes.NewBuffer(p.decryptRich(buff))

		if err := binary.Read(r2, binary.LittleEndian, &p.PeFile.RichHeader); err != nil {
			return err
		}
	}
	return nil
}

func (p *Parsed) parseNT(reader *bytes.Reader) error {
	p.setPointer(reader, uint64(p.PeFile.DosHeader.E_lfanew))

	if p.PeFile.DosHeader.E_lfanew < SIZE_OF_DOSH+SIZE_OF_DOSI {
		p.PeFile.Sabotages.AbnormalPE = true
	}

	if err := binary.Read(reader, binary.LittleEndian, &p.PeFile.NtHeaders); err != nil {
		return err
	}

	// NT Header flags modern PEs (1998+) and is mandatory.
	if p.PeFile.NtHeaders.Signature != IMAGE_NT_SIGNATURE {
		p.PeFile.Sabotages.AbnormalPE = true
		return errors.New("No NT Header, DOS era malware?")
	}

	return nil
}

func (p *Parsed) parseCOFF(reader *bytes.Reader) error {
	p.setPointer(reader, uint64(p.PeFile.DosHeader.E_lfanew+SIZE_OF_NTH))

	if err := binary.Read(reader, binary.LittleEndian, &p.PeFile.FileHeader); err != nil {
		return err
	}

	// There are malwares with 1 section, but that's literally illegal now.
	if p.PeFile.FileHeader.NumberOfSections < 2 {
		p.PeFile.Sabotages.AbnormalPE = true
	}

	// Optional header has 2 fixed sizes, or a stinky hand was in here.
	if p.PeFile.FileHeader.SizeOfOptionalHeader < SIZE_OF_OPT {
		p.PeFile.Sabotages.AbnormalPE = true
	}
	THIS_SIZE_OF_OPT = uint(p.PeFile.FileHeader.SizeOfOptionalHeader)

	// We do not care if these are not x32 or x64 PEs, and try to parse them anyway.
	// We do this to ensure malware ring0s also will be parsed, but it is not common to find modern drivers with the from architecture.
	if p.PeFile.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 {
		if p.PeFile.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 {
			p.PeFile.Sabotages.AbnormalPE = true
		}
	}

	if p.PeFile.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 {
		p.PeFile.isLargeAddress = true
	} else {
		p.PeFile.isLargeAddress = false
	}

	p.PeFile.COFFDetails = DecodeCOFFCharacts(uint16(p.PeFile.FileHeader.Characteristics))

	return nil
}

func (p *Parsed) parseOPT(reader *bytes.Reader) error {

	p.setPointer(reader, uint64(p.PeFile.DosHeader.E_lfanew+SIZE_OF_NTH+SIZE_OF_COFFH))

	if p.PeFile.isLargeAddress { // 64bit
		if err := binary.Read(reader, binary.LittleEndian, &p.PeFile.OptionalHeader); err != nil {
			return err
		}
		if p.PeFile.OptionalHeader.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS && p.PeFile.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 {
			p.PeFile.Sabotages.AbnormalPE = true
		}
	} else { // 32bit
		var opt32 OptionalHeader32
		if err := binary.Read(reader, binary.LittleEndian, &opt32); err != nil {
			return err
		}
		data, err := json.Marshal(opt32)
		if err != nil {
			return err
		}
		err = json.Unmarshal(data, &p.PeFile.OptionalHeader)
		if err != nil {
			return err
		}

		// A PE can't have different architecture specifications in 2 headers.
		if p.PeFile.OptionalHeader.Magic == OPTIONAL_HEADER_MAGIC_PE && p.PeFile.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 {
			p.PeFile.Sabotages.AbnormalPE = true
		}
	}

	p.PeFile.Indicators = DecodeDllCharacts(uint16(p.PeFile.OptionalHeader.DllCharacteristics))

	return nil
}

const (
	MAX_SECTION_SIZE = 0xFFFFFFFF
)

func (p *Parsed) parseSECT(reader *bytes.Reader) error {
	loopSeek := uint64(uint64(p.PeFile.DosHeader.E_lfanew + SIZE_OF_NTH + SIZE_OF_COFFH + uint32(THIS_SIZE_OF_OPT)))

	for index := 0; index < int(p.PeFile.FileHeader.NumberOfSections); index++ {
		var section SectionHeader
		p.setPointer(reader, uint64(loopSeek))

		if err := binary.Read(reader, binary.LittleEndian, &section.SectionHeaderRaw); err != nil {
			return err
		}

		section.Name = strings.TrimRight(string(section.SectionHeaderRaw.Name[:]), "\x00")

		p.PeFile.Sections = append(p.PeFile.Sections, section)
		loopSeek += 40
		DecodeCharacts(section)
	}

	for x, section := range p.PeFile.Sections {
		if section.SizeOfRawData > MAX_SECTION_SIZE {
			p.PeFile.Sabotages.AbnormalSectioning = true
		} else {
			data := make([]byte, section.SizeOfRawData)
			p.setPointer(reader, uint64(section.PointerToRawData))

			if err := binary.Read(reader, binary.LittleEndian, &data); err != nil {
				return err
			}

			entr := shannon.Shannon{}
			deep := spamsum.HashBytes(data)
			written, _ := entr.Write(data)
			if written != len(data) {
				return errors.New("Entropy failed.")
			}
			section.SSDeep = deep.String()
			section.Entropy = entr.SumFloat()
			//fmt.Printf("Entropy for %s is %f.\n", section.Name, section.Entropy)

			p.PeFile.Sections[x] = section
		}

	}

	if len(p.PeFile.Sections) > 0 {
		return nil
	}

	return errors.New("Empty sections...")
}

func readUTFString(buff []byte, offset uint64, size uint) string {
	var out string = ""
	for index := 0; uint(index) < size; index += 2 {
		out = out + string(buff[uint64(offset)+uint64(index)])
		if buff[uint64(offset)+uint64(index)] == 0 {
			break
		}
	}
	return string(out[:len(out)-1])
}

func readZeroTerminatedString(buff []byte) string {
	for i, b := range buff {
		if b == 0x00 {
			return string(buff[:i])
		}
	}
	return string(buff) // No zero termination found
}

func (p *Parsed) OrdinalResolver(path string) error {

	if (p.ordMap != nil) && (len(p.ordMap) > 0) {
		return nil
	} else {
		mappy, err := LoadResolveMaps(path)
		p.ordMap = mappy
		return err
	}

	return nil
}

func (p *Parsed) particularCases(reader *bytes.Reader) error {
	p.setPointer(reader, uint64(p.PeFile.OptionalHeader.Directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress))
	rawBuff := make([]byte, reader.Len())
	reader.Read(rawBuff)
	// InternalName
	rawPattern := [...]byte{0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65}
	index := bytes.Index(rawBuff, rawPattern[:])
	if index != -1 {
		p.PeFile.InternalName = readUTFString(rawBuff, uint64(index+len(rawPattern)+3), 0xFF)
	} else {
		//fmt.Printf("Internal name not found.\n")
	}
	// OriginalFileName
	rawPattern2 := [...]byte{0x4F, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65}
	index = bytes.Index(rawBuff, rawPattern2[:])
	if index != -1 {
		p.PeFile.OriginalName = readUTFString(rawBuff, uint64(index+len(rawPattern2)+3), 0xFF)
	} else {
		//fmt.Printf("Original File Name not found.\n")
	}

	return nil
}

var endingOpc = [...]uint8{0xC3, 0xCC, 0xC2}

func (p *Parsed) parseEP(reader *bytes.Reader) error {

	entryPoint := uint(uint64(p.PeFile.OptionalHeader.AddressOfEntryPoint))
	offset := GibMeOffset(p.PeFile.Sections, uint64(entryPoint))

	p.setPointer(reader, uint64(offset))
	data := make([]byte, EPSCAN_MAX_SIZE)
	reader.Read(data)

	var opTable [len(endingOpc)]uint8
	if p.PeFile.isLargeAddress {
		opTable = endingOpc
	} else {
		opTable = endingOpc
	}

	endoffunctionindex := 0
	for {
		if data[endoffunctionindex] == opTable[0] || data[endoffunctionindex] == opTable[1] || data[endoffunctionindex] == opTable[2] {
			break
		}
		endoffunctionindex++
		if endoffunctionindex >= len(data) {
			break
		}
	}

	ssd := spamsum.HashBytes(data[0:endoffunctionindex])
	p.PeFile.EPDeep = ssd.String()

	if p.signDb != nil {
		signs := p.signDb.MatchAll(data, RECOMMENDED_DEEPNESS, 0, true)
		if len(signs) > 0 {
			susp := false
			for _, s := range p.PeFile.Sections {
				if s.Entropy > 7.0 {
					susp = true
					break
				}
			}
			Packed := &PackerInfo{
				PackerName:   p.signDb.Entries[signs[0]].Name,
				EPOnly:       p.signDb.Entries[signs[0]].EntryPointOnly,
				HeavySuspect: susp,
			}
			p.PeFile.Packer = Packed
		}

		if strings.Compare(SCANTYPE_FULL, p.scantype) == 0 {
			noepsigns := p.signDb.MatchAll(p.data, RECOMMENDED_DEEPNESS, MAX_RECOMMENDED_SEARCH_SCANS, false)
			if len(noepsigns) > 0 {
				p.PeFile.Miscellanous = &Signatures{}
				for y, _ := range noepsigns {
					p.PeFile.Miscellanous.Signature = append(p.PeFile.Miscellanous.Signature, p.signDb.Entries[noepsigns[y]].Name)
				}
			}
		}
	}

	return nil
}

func (p *Parsed) parseDIRS(reader *bytes.Reader) error {
	p.PeFile.DataDirectory = make(map[DirectoryEntryType]interface{})
	var readDir int = 0
	for v, directory := range p.PeFile.OptionalHeader.Directories {
		if directory.VirtualAddress > 0 && directory.Size > 0 {

			// Directory can't be more than 1 GB, even if size is a uin32.
			if directory.Size < 1*1024*1024*1024 {

				var entry interface{}
				entry = directory // default import into DataDirectory index

				readDir++
				p.setPointer(reader, uint64(directory.VirtualAddress))

				switch DirectoryEntryType(v) {
				case IMAGE_DIRECTORY_ENTRY_EXPORT:

					sect := GetPointingSection(p.PeFile.Sections, uint64(directory.VirtualAddress))
					if sect != nil {
						pointer := GibMeOffset(p.PeFile.Sections, uint64(directory.VirtualAddress))
						if pointer > 0 && pointer < int64(len(p.data)) {

							p.setPointer(reader, uint64(pointer))
							var exportsHeader ExportDirectory
							rawStruct := make([]byte, binary.Size(ExportDirectory{}))
							reader.Read(rawStruct)

							// Reset pointer for parsing.
							p.setPointer(reader, uint64(pointer))
							if err := binary.Read(reader, binary.LittleEndian, &exportsHeader); err != nil {
								return err
							}

							// Sometimes exports are always the same between different versions and only function addresses might change...
							// Hashing everything except addresses might be a good idea.
							p.PeFile.ExpLeaks.EXPDeep = spamsum.HashBytes(rawStruct).String()

							addr, err := p.bytesrva(int(exportsHeader.Name), 0)
							if err != nil {
								break
							}
							dllName := readZeroTerminatedString(addr)
							p.PeFile.ExpLeaks.ActingName = dllName
							p.PeFile.ExpLeaks.CreationDate = exportsHeader.TimeDateStamp.String()
							p.PeFile.ExpLeaks.ExportedFunctions = int(exportsHeader.NumberOfFunctions)

							if p.PeFile.ExpLeaks.ExportedFunctions < 0 {
								p.PeFile.Sabotages.ScrambledAddresses = true
								break
							}

							var Entry ExportEntry
							var holder32 uint32
							var holder64 uint64
							var lastNameSize int = 0
							lastNameSize = 0
							for index := 0; index < int(exportsHeader.NumberOfFunctions); index++ {

								FunPointer := GibMeOffset(p.PeFile.Sections, uint64(exportsHeader.AddressOfFunctions+uint32(4*index)))
								OrdPointer := GibMeOffset(p.PeFile.Sections, uint64(exportsHeader.AddressOfNameOrdinals+uint32(4*index)))
								//NamePointer := GibMeOffset(p.PeFile.Sections, uint64(exportsHeader.AddressOfNames+uint32(4*index)))

								p.setPointer(reader, uint64(FunPointer))

								if p.PeFile.isLargeAddress {
									if err = binary.Read(reader, binary.LittleEndian, &holder64); err != nil {
										return err
									}
									Entry.Address = holder64
								} else {
									if err = binary.Read(reader, binary.LittleEndian, &holder32); err != nil {
										return err
									}
									Entry.Address = uint64(holder32)
								}

								p.setPointer(reader, uint64(OrdPointer))
								if err = binary.Read(reader, binary.LittleEndian, &Entry.Ordinal); err != nil {
									return err
								}
								/*
									fmt.Println(GibMeOffset(p.PeFile.Sections, uint64(NamePointer)))
									funName, err := p.bytesrva(int(NamePointer), 0)
									if err != nil {
										p.PeFile.Sabotages.ScrambledAddresses = true
										break
									}
								*/
								calcAddr := int(exportsHeader.Name) + int(len(p.PeFile.ExpLeaks.ActingName))
								off, err := p.bytes(calcAddr, 0)
								if err != nil {
									return err
								}
								Entry.Name = readZeroTerminatedString(off)
								lastNameSize = len(Entry.Name)

								fmt.Println(Entry)
							}

						} else {
							p.PeFile.Sabotages.DirectoryEvasion = true
						}
					}

				case IMAGE_DIRECTORY_ENTRY_IMPORT:
					p.PeFile.ImportedAPI = make(map[string][]ImportEntry)
					var lastOrd uint64 = 0

					var imphashparts []string

					sect := GetPointingSection(p.PeFile.Sections, uint64(directory.VirtualAddress))
					if sect != nil {
						pointer := GibMeOffset(p.PeFile.Sections, uint64(directory.VirtualAddress))

						//fmt.Printf("Import -> %s -> %08X\n", sect.Name, pointer)

						p.setPointer(reader, uint64(pointer))

						counter := directory.Size / uint32(binary.Size(ImportDescriptor{}))

						for index := 1; index < int(counter); index++ {
							var impDec ImportDescriptor

							if err := binary.Read(reader, binary.LittleEndian, &impDec); err != nil {
								return err
							}

							impdnameSet, err := p.bytes(int(GibMeOffset(p.PeFile.Sections, uint64(impDec.Name))), 0)
							if err != nil {
								break
							}
							impdname := readZeroTerminatedString(impdnameSet)
							//fmt.Printf("Import Descriptor (%08X) -> IAT %08X [copy %08X] (%v)\n", impDec.Name, impDec.OriginalFirstThunk, impDec.FirstThunk, name)

							rva := impDec.OriginalFirstThunk

							for {
								var addr []byte
								var oft uint64
								var name string
								var ordinal uint16
								if !p.PeFile.isLargeAddress {
									//dontCashMeOutside := GibMeOffset(p.PeFile.Sections, uint64(rva))
									//maxCashOutside := GibMeOffset(p.PeFile.Sections, uint64(directory.VirtualAddress+directory.Size))
									if rva == 0 {
										// RVA is 0, so entry is useless.
										break
									}
									addr, err = p.bytesrva(int(rva), 4)
									if len(addr) != 4 {
										break
									}
									addross := binary.BigEndian.Uint32(addr)
									if err != nil {
										break
									}
									if GibMeOffset(p.PeFile.Sections, uint64(addross)) >= int64(len(p.data)) {
										break
									}
									oft = uint64(binary.LittleEndian.Uint32(addr))

									if oft&0x80000000 != 0 {
										ordinal = uint16(oft & 0xFFFF)
									} else {
										// Repeated import, probably memory exhaustion attempt.
										if lastOrd == oft {
											break
										}
										lastOrd = oft

										ordSet, err := p.bytesrva(int(oft), 2)
										if err != nil {
											break
										}
										if len(ordSet) != 2 {
											p.PeFile.Sabotages.RecursiveIAT = true
											break
										}
										ordinal = binary.LittleEndian.Uint16(ordSet) // routine
										nameSet, err := p.bytesrva(int(oft+2), 0)
										if err != nil {
											break
										}
										name = readZeroTerminatedString(nameSet)

										if ordinal == 0 && len(name) < 1 {
											break
										}
									}

								} else {
									if rva == 0 {
										break
									}
									addr, err = p.bytesrva(int(rva), 8)
									if len(addr) != 8 {
										p.PeFile.Sabotages.RecursiveIAT = true
										break
									}
									addross := binary.BigEndian.Uint32(addr)
									if err != nil {
										break
									}
									if GibMeOffset(p.PeFile.Sections, uint64(addross)) >= int64(len(p.data)) {
										break
									}
									oft = uint64(binary.LittleEndian.Uint32(addr))

									if oft&0x8000000000000000 != 0 {
										ordinal = uint16(oft & 0xFFFF)
									} else {

										if lastOrd == oft {
											break
										}
										lastOrd = oft
										ordSet, err := p.bytesrva(int(oft), 2)
										if err != nil {
											break
										}

										if len(ordSet) != 2 {
											p.PeFile.Sabotages.RecursiveIAT = true
											break
										}
										ordinal = binary.LittleEndian.Uint16(ordSet) // routine

										nameSet, err := p.bytesrva(int(oft+2), 0)
										if err != nil {
											break
										}
										name = readZeroTerminatedString(nameSet)
									}
								}
								if oft == 0 {
									break
								}

								//fmt.Printf("Routine at %08X %d %v ...\n", oft, ordinal, name)
								if !p.PeFile.isLargeAddress {
									rva += 4
								} else {
									rva += 8
								}

								stuz := ImportEntry{
									Ordinal: uint(ordinal),
									Name:    name,
								}
								//if len(name) < 1 && stuz.Ordinal > 0 && stuz.Ordinal < 1000 {
								//	stuz.Name = p.resolveOrdinal(int(stuz.Ordinal), impdname)
								//} else {
								//	break
								//}

								// IAT might be a huge file name, that happens when is encrypted or faked.
								if len(name) < 350 {
									if len(p.PeFile.ImportedAPI[impdname]) < 500 {
										p.PeFile.ImportedAPI[impdname] = append(p.PeFile.ImportedAPI[impdname], stuz)
									} else {
										// Too many entries, you can't have more than 500 imports, realistically speaking
										// Might be a memory exhaustion attempt.
										p.PeFile.Sabotages.RecursiveIAT = true
										break
									}

								} else {
									p.PeFile.Sabotages.HeavilyEncrypted = true
									//fmt.Printf("Imported API: encrypted -> %s...[+%d more]\n", name[:350], len(name)-350)
								}

								if len(impdname) > 1 && len(name) > 0 && ordinal > 0 {
									//imphashparts = append(imphashparts, fmt.Sprintf("%s.%s", strings.ToLower(impdname[:len(impdname)-4]), strings.ToLower(name)))
								}

							}
						}
						//h := md5.New()
						//h.Write([]byte(strings.Join(imphashparts, ",")))
						//p.PeFile.ImpHash = string(hex.EncodeToString(h.Sum(nil)))
						p.PeFile.ImpHash = strings.Join(imphashparts, ",")
					}
				case IMAGE_DIRECTORY_ENTRY_RESOURCE:
					// not important, but some droppers store an encrypted payload version in resources, might be usefull
					/*
						sect := GetPointingSection(p.PeFile.Sections, uint64(directory.VirtualAddress))
						if sect != nil {
							pointer := PtrToRVA(uint64(directory.VirtualAddress), uint64(sect.VirtualAddress), uint64(sect.PointerToRawData))
							p.setPointer(reader, uint64(pointer))
							var resourceHeader ResourceDirectory

							if err := binary.Read(reader, binary.LittleEndian, &resourceHeader); err != nil {
								return err
							}

							p.setPointer(reader, uint64(pointer+0x10))

							for index := 0; index < int(resourceHeader.NumberOfNamedEntries+resourceHeader.NumberOfIdEntries); index++ {
								var resourceDirEntry ResourceDirectoryEntry
								if err := binary.Read(reader, binary.LittleEndian, &resourceDirEntry); err != nil {
									return err
								}

								//fmt.Printf("Dir ID %d @ %08X\n", resourceDirEntry.Name, resourceDirEntry.OffsetToData)

								p.PeFile.DirectoryEntries = append(p.PeFile.DirectoryEntries, resourceDirEntry)
								p.setPointer(reader, uint64(pointer+0x10+int64(binary.Size(ResourceDirectoryEntry{})*index)))
								//fmt.Printf("%08X\n", uint64(pointer+0x10+int64(binary.Size(ResourceDirectoryEntry{})*index)))

							}

							for _, c := range p.PeFile.DirectoryEntries {
								var resourceData ResourceDataEntry
								isNamed := (c.Name & 0x80000000) >> 31
								if isNamed != 0 {
									c.Name = (c.Name & 0x00FFFFFF)
									//name := readZeroTerminatedString(p.bytesrva(int(c.Name), 0))
									//fmt.Printf("> %s\n", name)
								} else {
									c.Name = (c.Name & 0x00FFFFFF)
								}

								//fmt.Printf("> %d - %08X\n", c.Name, GibMeOffset(p.PeFile.Sections, uint64(c.OffsetToData)))

								p.setPointer(reader, uint64(GibMeOffset(p.PeFile.Sections, uint64(c.OffsetToData))))
								if err := binary.Read(reader, binary.LittleEndian, &resourceData); err != nil {
									return err
								}

								//fmt.Printf("Size Dir: %d %08X\n", resourceData.Size, uint64(GibMeOffset(p.PeFile.Sections, uint64(resourceData.OffsetToData))))
							}
							entry = resourceHeader
						} else {
							fmt.Printf("Resource directory not pointing to anywhere, typical packed behaviour\n")
						}
					*/

				case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
					// not important, some PE perform hooking trough PAGE_GUARD exception calling, rarely in
					// the hacking scene.

					sect := GetPointingSection(p.PeFile.Sections, uint64(directory.VirtualAddress))
					if sect != nil {
						pointer := GibMeOffset(p.PeFile.Sections, uint64(directory.VirtualAddress)) //PtrToRVA(uint64(p.PeFile.OptionalHeader64.Directories[v].VirtualAddress), uint64(sect.VirtualAddress), uint64(sect.PointerToRawData))
						p.setPointer(reader, uint64(pointer))

						// not going deeper, for now.
					}
				case IMAGE_DIRECTORY_ENTRY_SECURITY:
					headerInfo := make([]byte, SIZE_WIN_CERTIFICATE_HDR)

					p.setPointer(reader, uint64(directory.VirtualAddress))
					red, err := reader.Read(headerInfo)
					if err != nil {
						return err
					} else if red != SIZE_WIN_CERTIFICATE_HDR {
						return errors.New("Didn't read 8 bytes during security directory header reading, something's wrong.")
					}

					readeri := bytes.NewReader(headerInfo)
					binary.Read(readeri, binary.LittleEndian, &p.PeFile.AuthInfo.Certificate.Length)
					binary.Read(readeri, binary.LittleEndian, &p.PeFile.AuthInfo.Certificate.Revision)
					binary.Read(readeri, binary.LittleEndian, &p.PeFile.AuthInfo.Certificate.CerificateType)

					if p.PeFile.AuthInfo.Certificate.CerificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA || p.PeFile.AuthInfo.Certificate.CerificateType == WIN_CERT_TYPE_X509 {
						if p.PeFile.AuthInfo.Certificate.Revision == WIN_CERT_REVISION_1_0 || p.PeFile.AuthInfo.Certificate.Revision == WIN_CERT_REVISION_2_0 {
							p.PeFile.AuthInfo.Certificate.Certificate = make([]byte, directory.Size-SIZE_WIN_CERTIFICATE_HDR)

							p.setPointer(reader, uint64(directory.VirtualAddress+SIZE_WIN_CERTIFICATE_HDR))

							red, err := reader.Read(p.PeFile.AuthInfo.Certificate.Certificate)

							if err != nil {
								return err
							} else if uint64(red) != uint64(p.PeFile.AuthInfo.Certificate.Length-SIZE_WIN_CERTIFICATE_HDR) {
								return errors.New("Didn't read real length of certificate, something's wrong.")
							}

							p.PeFile.AuthInfo.Path = p.Path
							//p.PeFile.AuthRes = p.PeFile.AuthInfo.Validate()
							//p.PeFile.AuthInfo.DeptInfo = *p.PeFile.AuthInfo.GetInDeptInfo()
							au := Authenticode{}
							au.Initialize(0, 0, int(p.PeFile.AuthInfo.Certificate.RealLength), p.PeFile.AuthInfo.Certificate.Certificate)
							p.PeFile.AuthRes = au.Parse()
							if !p.PeFile.AuthRes {
								// Happens when it's reading an old COPYRIGHT format or if signature is wrong revision (1) or when simply it's a bunch of junk bytes or encrypted stuff.
								//fmt.Printf("Warning: Authenticode certificate failed to be parsed.\n")
								p.PeFile.AuthRes = false
							}
							p.PeFile.AuthInfoGo = au
							p.PeFile.AuthInfo.Certificate.Certificate = nil
						}
					}

				case IMAGE_DIRECTORY_ENTRY_BASERELOC:
					// useless for us
				case IMAGE_DIRECTORY_ENTRY_DEBUG:
					// might contain usefull info on compilation of pe
					// Raw data of entry vary from compiler to compiler.
					sect := GetPointingSection(p.PeFile.Sections, uint64(directory.VirtualAddress))
					if sect != nil {
						pointer := GibMeOffset(p.PeFile.Sections, uint64(directory.VirtualAddress)) //PtrToRVA(uint64(p.PeFile.OptionalHeader64.Directories[v].VirtualAddress), uint64(sect.VirtualAddress), uint64(sect.PointerToRawData))
						p.setPointer(reader, uint64(pointer))
						var debugDir DebugDirectory
						var rsdsEntry RSDSEntry

						//fmt.Printf("Debug -> %s -> %08X\n", string(sect.Name[:]), pointer)
						if err := binary.Read(reader, binary.LittleEndian, &debugDir); err != nil {
							return err
						}

						p.setPointer(reader, uint64(debugDir.PointerToRawData)+24)
						var pdbStringSize int = 0
						for {
							var btrPlaceHolder byte
							if err := binary.Read(reader, binary.LittleEndian, &btrPlaceHolder); err != nil {
								return err
							}
							pdbStringSize++
							if btrPlaceHolder == 0x00 {
								break
							}
						}
						rsdsEntry.Name = make([]byte, pdbStringSize)

						p.setPointer(reader, uint64(debugDir.PointerToRawData))
						if err := binary.Read(reader, binary.LittleEndian, &rsdsEntry.Magic); err != nil {
							return err
						}
						if err := binary.Read(reader, binary.LittleEndian, &rsdsEntry.Hash); err != nil {
							return err
						}
						if err := binary.Read(reader, binary.LittleEndian, &rsdsEntry.PDBFiles); err != nil {
							return err
						}
						if err := binary.Read(reader, binary.LittleEndian, &rsdsEntry.Name); err != nil {
							return err
						}

						entry = rsdsEntry
					} else {
						p.PeFile.Sabotages.DirectoryEvasion = true
						//fmt.Printf("Debug directory not pointing to anywhere, typical packed behaviour\n")
						// Left over of a packer that might have removed the debug info but left pointers to confuse REnegineers.
					}
				case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
					// useless, should contain architecture info, rarely seen.
				case IMAGE_DIRECTORY_ENTRY_RESERVED:
					// useless
				case IMAGE_DIRECTORY_ENTRY_TLS:
					// threads global vars and semaphores/mutexes, actually useless.
				case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
					// useless
				case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
					// might be usefull
				case IMAGE_DIRECTORY_ENTRY_IAT:
					// fundamental
				case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
					// not used anymore, GetProcAddress replaced the use of this.
				case IMAGE_DIRECTORY_ENTRY_CLR_DESCRIPTOR:
					// CLR/.NET metadata, might be usefull.
				default:
					return errors.New("Out of directory scanning index, this should never happen.")
					// This happens if the number of directories in OPt header is more than 16, which means it has been manually edited to scramble stuff.
				}

				if entry != nil {
					p.PeFile.DataDirectory[DirectoryEntryType(v)] = entry
				}
			} else {
				//fmt.Printf("Section %d is way more large than possible.\n", v)
				p.PeFile.Sabotages.IncorrectSizes = true
			}
		}

	}

	return nil
}

func (p *Parsed) getHash(reader *bytes.Reader) string {
	distanceToChecksum := 0x40
	offsetPreChecksum := int(SIZE_OF_DOSH + SIZE_OF_NTH + SIZE_OF_DOSI + int(THIS_SIZE_OF_RICH) + SIZE_OF_COFFH + distanceToChecksum)
	mappedSections := make(map[uint32]SectionHeader, p.PeFile.FileHeader.NumberOfSections)

	sha256 := sha256.New()
	preChecksum := make([]byte, offsetPreChecksum)
	p.setPointer(reader, 0)
	binary.Read(reader, binary.BigEndian, preChecksum)

	var postChecksumSize int = 0
	if p.PeFile.isLargeAddress {
		postChecksumSize = int(THIS_SIZE_OF_OPT - 68)
	} else {
		postChecksumSize = int(THIS_SIZE_OF_OPT - 64)
	}

	p.setPointer(reader, uint64(offsetPreChecksum+4))
	postChecksum := make([]byte, postChecksumSize)
	reader.Read(postChecksum)

	postChecksumPreSecurity := make([]byte, int(p.PeFile.FileHeader.SizeOfOptionalHeader)-4-40+(binary.Size(DataDirectoryEntry{})*int(IMAGE_DIRECTORY_ENTRY_SECURITY)))
	reader.Read(postChecksumPreSecurity)
	p.setPointer(reader, uint64(len(postChecksumPreSecurity)+8))
	postSecurity := make([]byte, int(p.PeFile.OptionalHeader.SizeOfHeaders)-(len(postChecksumPreSecurity)+8))
	reader.Read(postSecurity)

	//var SUM_OF_BYTES_HASHED uint = uint(p.PeFile.OptionalHeader.SizeOfHeaders)
	for _, s := range p.PeFile.Sections {
		mappedSections[s.PointerToRawData] = s
	}

	return hex.EncodeToString(sha256.Sum([]byte("-")))
}

func (p *Parsed) parseResourceDir(offset, size uint64) {

}

func checkError(err error) bool {
	if err != nil {
		return true
	}

	return false
}

func (p *Parsed) bytesrva(offset, length int) ([]byte, error) {
	return p.bytes(int(GibMeOffset(p.PeFile.Sections, uint64(offset))), length)
}

func (p *Parsed) bytes(offset, length int) ([]byte, error) {
	if p.data == nil { // No data
		return []byte{0}, errors.New("No data")
	}
	if offset >= len(p.data) { // Not enough data
		//fmt.Println("not enough data...", offset, ">", len(p.data))
		return []byte{0}, errors.New("Not enough data")
	}
	end := offset + length
	if length == 0 {
		end = len(p.data)
	} else if end >= len(p.data) {
		end = len(p.data)
	}
	return p.data[offset:end], nil
}

func (p *Parsed) adjustValues() error {

	// File Alignment adjusting
	p.PeFile.FileAlignment = (uint32(p.PeFile.OptionalHeader.FileAlignment / ALIGNMENT_STANDARD_VALUE)) * ALIGNMENT_STANDARD_VALUE

	return nil
}

func (p *Parsed) loadSignatures(types string, dbpath string) error {
	if p.signDb != nil {
		return nil
	} else {
		if strings.Compare(SCANTYPE_OFF, types) == 0 {
			p.signDb = nil
		} else if strings.Compare(SCANTYPE_FULL, types) == 0 || strings.Compare(SCANTYPE_EPONLY, types) == 0 {
			db, err := LoadSignatures(dbpath)
			if err != nil {
				return err
			} else {
				p.signDb = db
			}
		}
	}

	return nil
}

func (p *Parsed) Parse(buffer []byte, scantype string, dbpath string) error {
	if len(p.Path) < 1 {
		return errors.New("No path given")
	}

	err := p.loadSignatures(scantype, dbpath)
	p.scantype = scantype
	if err != nil {
		return err
	}

	p.data = buffer
	defer func() {
		p.data = nil
		p.signDb = nil
		p.ordMap = nil
	}() // forget it and clean everything

	if len(buffer) > 1 {

		reader := bytes.NewReader(buffer)

		err := p.parseDOS(reader)
		if checkError(err) {
			return err
		}

		err = p.parseRich(reader)
		if checkError(err) {
			return err
		}

		err = p.parseNT(reader)
		if checkError(err) {
			return err
		}

		err = p.parseCOFF(reader)
		if checkError(err) {
			return err
		}

		err = p.parseOPT(reader)
		if checkError(err) {
			return err
		}

		p.adjustValues()

		err = p.parseSECT(reader)
		if checkError(err) {
			return err
		}

		err = p.parseDIRS(reader)
		if checkError(err) {
			return err
		}

		err = p.particularCases(reader)
		if checkError(err) {
			return err
		}

		err = p.parseEP(reader)
		if checkError(err) {
			return err
		}

		//p.PeFile.AuthHash = p.getHash(reader)

		return nil // Success
	}

	return errors.New("No buffer parsed.")
}

func (p *Parsed) LoadWithSignatures(path, scantype, dbfile string) error {
	buffer, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	p.Path = path
	return p.Parse(buffer, scantype, dbfile)
}

func (p *Parsed) Load(path string) error {
	buffer, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	p.Path = path
	return p.Parse(buffer, SCANTYPE_OFF, "")
}
