package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/x-way/pktdump"

	nflog "github.com/florianl/go-nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {

	var (
		dumpDuration      = flag.Duration("t", 10*time.Second, "how long to run the NFLOG dumping")
		iface             = flag.String("i", "any", "incoming interface to listen on (default: any)")
		mode              = flag.String("m", "tunnel", "IPSec mode (tunnel or transport)")
		tunnelSource      = flag.String("s", "", "IPSec tunnel source IP")
		tunnelDestination = flag.String("d", "", "IPSec tunnel destination IP")
		nflogGroup        = flag.Int("g", 5050, "NFLOG group to use")
	)

	flag.Parse()

	if err := validateFlags(*mode, *tunnelSource, *tunnelDestination); err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	prefix := fmt.Sprintf("ipsecdump:%d", os.Getpid())

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

	addCmd := exec.Command("iptables", buildIptablesParams(false, *mode, *iface, *tunnelSource, *tunnelDestination, *nflogGroup, prefix)...)
	delCmd := exec.Command("iptables", buildIptablesParams(true, *mode, *iface, *tunnelSource, *tunnelDestination, *nflogGroup, prefix)...)

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

func validateFlags(mode, tunnelSource, tunnelDestination string) error {
	if mode != "tunnel" && mode != "transport" {
		return fmt.Errorf("mode must be 'tunnel' or 'transport'")
	}
	if mode == "transport" && ((tunnelSource != "") || (tunnelDestination != "")) {
		return fmt.Errorf("transport mode does not support tunnel source/destination IPs")
	}
	if tunnelSource != "" && net.ParseIP(tunnelSource) == nil {
		return fmt.Errorf("tunnel source IP must be a valid IP address")
	}
	if tunnelDestination != "" && net.ParseIP(tunnelDestination) == nil {
		return fmt.Errorf("tunnel destination IP must be a valid IP address")
	}
	return nil
}

func buildIptablesParams(del bool, mode, iface, tunnelSource, tunnelDestination string, nflogGroup int, prefix string) []string {
	var params []string

	if del {
		params = append(params, "-D")
	} else {
		params = append(params, "-I")
	}

	params = append(params, []string{"PREROUTING", "-t", "raw"}...)
	if iface != "any" {
		params = append(params, "-i", iface)
	}

	params = append(params, []string{"-m", "policy", "--dir", "in", "--pol", "ipsec", "--mode", mode, "--proto", "esp"}...)
	if mode == "tunnel" {
		if tunnelSource != "" {
			params = append(params, "--tunnel-src", tunnelSource)
		}
		if tunnelDestination != "" {
			params = append(params, "--tunnel-dst", tunnelDestination)
		}
	}

	params = append(params, "-j", "NFLOG", "--nflog-group", fmt.Sprintf("%d", nflogGroup), "--nflog-prefix", prefix)

	return params
}
