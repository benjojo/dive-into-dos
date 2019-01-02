package main

import (
	"fmt"
	"log"
	"net"

	gdb "github.com/benjojo/dive-into-dos/remotegdb"
)

func main() {
	fmt.Print(".")

	opCodes := make(map[string]string)

	opCodes["00"] = "Program terminate"
	opCodes["01"] = "Keyboard input with echo"
	opCodes["02"] = "Display output"
	opCodes["03"] = "Wait for auxiliary device input"
	opCodes["04"] = "Auxiliary output"
	opCodes["05"] = "Printer output"
	opCodes["06"] = "Direct console I/O"
	opCodes["07"] = "Wait for direct console input without echo"
	opCodes["08"] = "Wait for console input without echo"
	opCodes["09"] = "Print string"
	opCodes["0a"] = "Buffered keyboard input"
	opCodes["0b"] = "Check standard input status"
	opCodes["0c"] = "Clear keyboard buffer, invoke keyboard function"
	opCodes["0d"] = "Disk reset"
	opCodes["0e"] = "Select disk"
	opCodes["0f"] = "Open file using FCB"
	opCodes["10"] = "Close file using FCB"
	opCodes["11"] = "Search for first entry using FCB"
	opCodes["12"] = "Search for next entry using FCB"
	opCodes["13"] = "Delete file using FCB"
	opCodes["14"] = "Sequential read using FCB"
	opCodes["15"] = "Sequential write using FCB"
	opCodes["16"] = "Create a file using FCB"
	opCodes["17"] = "Rename file using FCB"
	opCodes["18"] = "DOS dummy function (CP/M) (not used/listed)"
	opCodes["19"] = "Get current default drive"
	opCodes["1a"] = "Set disk transfer address"
	opCodes["1b"] = "Get allocation table information"
	opCodes["1c"] = "Get allocation table info for specific device"
	opCodes["1d"] = "DOS dummy function (CP/M) (not used/listed)"
	opCodes["1e"] = "DOS dummy function (CP/M) (not used/listed)"
	opCodes["1f"] = "Get pointer to default drive parameter table (undocumented)"
	opCodes["20"] = "DOS dummy function (CP/M) (not used/listed)"
	opCodes["21"] = "Random read using FCB"
	opCodes["22"] = "Random write using FCB"
	opCodes["23"] = "Get file size using FCB"
	opCodes["24"] = "Set relative record field for FCB"
	opCodes["25"] = "Set interrupt vector"
	opCodes["26"] = "Create new program segment"
	opCodes["27"] = "Random block read using FCB"
	opCodes["28"] = "Random block write using FCB"
	opCodes["29"] = "Parse filename for FCB"
	opCodes["2a"] = "Get date"
	opCodes["2b"] = "Set date"
	opCodes["2c"] = "Get time"
	opCodes["2d"] = "Set time"
	opCodes["2e"] = "Set/reset verify switch"
	opCodes["2f"] = "Get disk transfer address"
	opCodes["30"] = "Get DOS version number"
	opCodes["31"] = "Terminate process and remain resident"
	opCodes["32"] = "Get pointer to drive parameter table (undocumented)"
	opCodes["33"] = "Get/set Ctrl-Break check state & get boot drive"
	opCodes["34"] = "Get address to DOS critical flag (undocumented)"
	opCodes["35"] = "Get vector"
	opCodes["36"] = "Get disk free space"
	opCodes["37"] = "Get/set switch character (undocumented)"
	opCodes["38"] = "Get/set country dependent information"
	opCodes["39"] = "Create subdirectory (mkdir)"
	opCodes["3a"] = "Remove subdirectory (rmdir)"
	opCodes["3b"] = "Change current subdirectory (chdir)"
	opCodes["3c"] = "Create file using handle"
	opCodes["3d"] = "Open file using handle"
	opCodes["3e"] = "Close file using handle"
	opCodes["3f"] = "Read file or device using handle"
	opCodes["40"] = "Write file or device using handle"
	opCodes["41"] = "Delete file"
	opCodes["42"] = "Move file pointer using handle"
	opCodes["43"] = "Change file mode"
	opCodes["44"] = "I/O control for devices (IOCTL)"
	opCodes["45"] = "Duplicate file handle"
	opCodes["46"] = "Force duplicate file handle"
	opCodes["47"] = "Get current directory"
	opCodes["48"] = "Allocate memory blocks"
	opCodes["49"] = "Free allocated memory blocks"
	opCodes["4a"] = "Modify allocated memory blocks"
	opCodes["4b"] = "EXEC load and execute program (func 1 undocumented)"
	opCodes["4c"] = "Terminate process with return code"
	opCodes["4d"] = "Get return code of a sub-process"
	opCodes["4e"] = "Find first matching file"
	opCodes["4f"] = "Find next matching file"
	opCodes["50"] = "Set current process id (undocumented)"
	opCodes["51"] = "Get current process id (undocumented)"
	opCodes["52"] = "Get pointer to DOS \"INVARS\" (undocumented)"
	opCodes["53"] = "Generate drive parameter table (undocumented)"
	opCodes["54"] = "Get verify setting"
	opCodes["55"] = "Create PSP (undocumented)"
	opCodes["56"] = "Rename file"
	opCodes["57"] = "Get/set file date and time using handle"
	opCodes["58"] = "Get/set memory allocation strategy (3.x+, undocumented)"
	opCodes["59"] = "Get extended error information (3.x+)"
	opCodes["5a"] = "Create temporary file (3.x+)"
	opCodes["5b"] = "Create new file (3.x+)"
	opCodes["5c"] = "Lock/unlock file access (3.x+)"
	opCodes["5d"] = "Critical error information (undocumented 3.x+)"
	opCodes["5e"] = "Network services (3.1+)"
	opCodes["5f"] = "Network redirection (3.1+)"
	opCodes["60"] = "Get fully qualified file name (undocumented 3.x+)"
	opCodes["62"] = "Get address of program segment prefix (3.x+)"
	opCodes["63"] = "Get system lead byte table (MSDOS 2.25 only)"
	opCodes["64"] = "Set device driver look ahead  (undocumented 3.3+)"
	opCodes["65"] = "Get extended country information (3.3+)"
	opCodes["66"] = "Get/set global code page (3.3+)"
	opCodes["67"] = "Set handle count (3.3+)"
	opCodes["68"] = "Flush buffer (3.3+)"
	opCodes["69"] = "Get/set disk serial number (undocumented DOS 4.0+)"
	opCodes["6a"] = "DOS reserved (DOS 4.0+)"
	opCodes["6b"] = "DOS reserved"
	opCodes["6c"] = "Extended open/create (4.x+)"
	opCodes["F8"] = "Set OEM INT 21 handler (functions F9-FF) (undocumented)"

	c, err := net.Dial("tcp", "localhost:1234")
	if err != nil {
		log.Fatalf("failed to dial %s", err.Error())
	}

	g := gdb.NewConnection(c)
	for {
		g.SetBreakpoint(0x4289, true)
		g.Continue()
		g.UnsetBreakpoint(0x4289, true)
		g.Step()
		R, err := g.GetRegisters()
		if err != nil {
			log.Fatalf("failed to register %s", err.Error())
		}

		fmt.Printf("AH: %02x AKA: %s\n", R.Al, opCodes[fmt.Sprintf("%02x", R.Al)])
	}
}
