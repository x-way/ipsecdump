package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/x-way/pktdump"
	"log"
	"os"
	"os/exec"
	"time"

	nflog "github.com/florianl/go-nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var nflogGroup = flag.Int("g", 5050, "NFLOG group to use")
var dumpDuration = flag.Duration("t", 10*time.Second, "how long to run the NFLOG dumping")
var mode = flag.String("m", "tunnel", "IPSec mode (tunnel or transport)")
var tunnelSource = flag.String("s", "", "IPSec tunnel source IP")
var tunnelDestination = flag.String("d", "", "IPSec tunnel destination IP")
var iface = flag.String("i", "any", "incoming interface to listen on (default: any)")

func main() {
	flag.Parse()

	prefix := fmt.Sprintf("ipsecdump:%d", os.Getpid())

	if *mode != "tunnel" && *mode != "transport" {
		fmt.Println("Error: -m parameter only supports 'tunnel' or 'transport'")
		return
	}
	if *mode == "transport" && ((*tunnelSource != "") || (*tunnelDestination != "")) {
		fmt.Println("Error: transport mode does not support tunnel source/destination IPs")
		return
	}

	config := nflog.Config{
		Group:       uint16(*nflogGroup),
		Copymode:    nflog.NfUlnlCopyPacket,
		ReadTimeout: time.Second,
	}

	nfl, err := nflog.Open(&config)
	if err != nil {
		log.Fatal(fmt.Sprintf("Could not open nflog socket: %v\n", err))
	}
	defer nfl.Close()

	fn := func(attrs nflog.Attribute) int {
		if attrs.Payload != nil && attrs.HwProtocol != nil && attrs.Prefix != nil && *attrs.Prefix == prefix {
			switch *attrs.HwProtocol {
			case 0x0008:
				fmt.Printf("%s ", time.Now().Format("15:04:05.000000"))
				fmt.Println(pktdump.Format(gopacket.NewPacket(*attrs.Payload, layers.LayerTypeIPv4, gopacket.Default)))
			case 0xdd86:
				fmt.Printf("%s ", time.Now().Format("15:04:05.000000"))
				fmt.Println(pktdump.Format(gopacket.NewPacket(*attrs.Payload, layers.LayerTypeIPv6, gopacket.Default)))
			}
		}

		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), *dumpDuration)
	defer cancel()

	if err := nfl.Register(ctx, fn); err != nil {
		log.Fatal(fmt.Sprintf("Could not register nflog callback: %v\n", err))
	}

	params := []string{"PREROUTING", "-t", "raw", "-m", "policy", "--dir", "in", "--pol", "ipsec", "--mode", *mode, "--proto", "esp"}
	if *iface != "any" {
		params = append(params, "-i", *iface)
	}
	if *tunnelSource != "" {
		params = append(params, "--tunnel-src", *tunnelSource)
	}
	if *tunnelDestination != "" {
		params = append(params, "--tunnel-dst", *tunnelDestination)
	}
	params = append(params, "-j", "NFLOG", "--nflog-group", fmt.Sprintf("%d", *nflogGroup), "--nflog-prefix", prefix)

	addCmd := exec.Command("iptables", append([]string{"-I"}, params...)...)
	delCmd := exec.Command("iptables", append([]string{"-D"}, params...)...)

	defer func() {
		if err := delCmd.Run(); err != nil {
			fmt.Printf("Command finished with error: %s\n", err)
		}
	}()
	if err := addCmd.Run(); err != nil {
		fmt.Printf("Command finished with error: %s\n", err)
	}

	<-ctx.Done()
}
