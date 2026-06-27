//go:build darwin

package tun

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ctlInfo struct {
	Id   uint32
	Name [96]byte // MAX_KCTL_NAME is exactly 96 bytes in macOS
}

// start local interceptor
func Start() {
	fmt.Println("asking mac os for a UTUN interface")

	//create system socket (mac os things)
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		log.Fatalf("failed to create system socket: %v, err")
	}

	info := &ctlInfo{}
	copy(info.Name[:], []byte("com.apple.net.utun_control"))

	// 3. Make the raw syscall to CTLIOCGINFO (Get Control Info)
	// 0xC0644E03 is the raw hexadecimal value for the CTLIOCGINFO command in the macOS kernel.
	// We use unsafe.Pointer to hand the kernel the memory address of our info struct so it can write the ID into it.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0xC0644E03), uintptr(unsafe.Pointer(info)))
	if errno != 0 {
		log.Fatalf("Failed to get ctl info via raw syscall: %v", errno)
	}

	// 4. Connect to the Apple UTUN Control subsystem using the ID the kernel just wrote into our struct
	ctlAddr := &unix.SockaddrCtl{
		ID:   info.Id,
		Unit: 0, // Let the OS pick the next available utun number
	}

	if err := unix.Connect(fd, ctlAddr); err != nil {
		log.Fatalf("Failed to connect to utun control: %v", err)
	}

	// which interface was assigned, get name from kernal
	name, err := unix.GetsockoptString(fd, 2, 2)
	if err != nil {
		log.Fatalf("Failed to get utun name: %v", err)
	}
	fmt.Printf("Successfully allocated virtual interface: %s\n", name)

	tunFile := os.NewFile(uintptr(fd), name)

	fmt.Println("Listening for raw IP packets. Send traffic to this interface!")
	packet := make([]byte, 1500) // 1500 bytes is the standard Maximum Transmission Unit (MTU) for a network packet

	for {
		// read a raw packet from the operating system
		n, err := tunFile.Read(packet)
		if err != nil {
			log.Fatalf("Error reading from TUN: %v", err)
		}

		// os attaches a 4byte header to the front of the packet on mac
		// ip packet starts at index 4
		rawIPPacket := packet[4:n]

		// print the raw bytes to the terminal
		fmt.Printf("\n--- Intercepted Packet (%d bytes) ---\n", len(rawIPPacket))
		fmt.Println(hex.Dump(rawIPPacket))
	}
}
