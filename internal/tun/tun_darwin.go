//go:build darwin

package tun

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

// start local interceptor
func Start() {
	fmt.Println("asking mac os for a UTUN interface")

	//create system socket (mac os things)
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		log.Fatalf("failed to create system socket: %v, err")
	}

	//connect to apple utun control

	ctlInfo := &unix.SockaddrCtl{
		ID:   0,
		Unit: 0,
	}

	copy(ctlInfo.Name[:], []byte("com.apple.net.utun_control"))

	if err := unix.Connect(fd, ctlInfo); err != nil {
		log.Fatalf("Failed to connect to utun control: %v", err)
	}

	// which interface was assigned, get name from kernal
	name, err := unix.GetsockoptString(fd, unix.SYSPROTO_CONTROL, 2)
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
