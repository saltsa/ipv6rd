// Configures 6rd tunnel to Linux host
// To use this, run it from dhcp client. In NetworkManager environments this
// application should be place in /etc/NetworkManager/dispatcher.d

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type iprouteOP string
type iprouteGroup string

const (
	IPRouteOPAdd    iprouteOP = "add"
	IPRouteOPDelete iprouteOP = "delete"
	IPRouteOPSet    iprouteOP = "set"

	IPRouteGroupAddr   iprouteGroup = "addr"
	IPRouteGroupTunnel iprouteGroup = "tunnel"
	IPRouteGroupLink   iprouteGroup = "link"
	IPRouteGroupRoute  iprouteGroup = "route"
)

const deviceName6rd = "6rd"
const EnvOption6rd = "DHCP4_OPTION_6RD"
const EnvDispatcherAction = "NM_DISPATCHER_ACTION"
const EnvOwnIP = "DHCP4_IP_ADDRESS"

func getIPv6Net(v6NetPrefix netip.Addr, ownIP netip.Addr, ipv4MaskLen int, sixrdPrefixLen int) (netip.Addr, error) {
	// RFC5969 allows even 0 but we limit to 16
	if ipv4MaskLen < 16 || ipv4MaskLen > 32 {
		return netip.Addr{}, errors.New("invalid v4 masklen")
	}

	v4UsableBits := 32 - ipv4MaskLen
	// RFC5969 allows even 128 but we limit it to 64
	if v4UsableBits+sixrdPrefixLen > 64 {
		return netip.Addr{}, errors.New("invalid ipv4masklen and sixrdprefixlen")
	}

	if sixrdPrefixLen < 32 {
		return netip.IPv4Unspecified(), errors.New("invalid sixrdPrefixLen")
	}

	if !v6NetPrefix.Is6() {
		return netip.Addr{}, errors.New("invalid IPv6 prefix")
	}

	if !ownIP.Is4() || !ownIP.IsGlobalUnicast() || ownIP.IsPrivate() {
		return netip.Addr{}, errors.New("invalid IPv4 address")
	}

	// convert addresses to big.Int types
	ipv4Int := &big.Int{}
	_v4AddrBytes := ownIP.As4()
	ipv4Int.SetBytes(_v4AddrBytes[:])

	prefixInt := &big.Int{}
	_v6NetBytes := v6NetPrefix.As16()
	prefixInt.SetBytes(_v6NetBytes[:])

	// from ipv4, mask the ipv4MaskLen rightmost bits with AND and then shift them right after sixrdPrefixLen
	ipv4Int.And(ipv4Int, big.NewInt((1<<v4UsableBits)-1))
	ipv4Int.Lsh(ipv4Int, uint(128-sixrdPrefixLen-v4UsableBits))

	// OR ipv4 int with the v6Prefix
	myv6AddrB := prefixInt.Or(prefixInt, ipv4Int)
	// use ::666 address by default, can be anything else too
	myv6AddrB.Or(myv6AddrB, big.NewInt(1638))

	myv6Addr := netip.AddrFrom16([16]byte(myv6AddrB.Bytes()))
	log.Printf("6rdPrefixLen=%d ipv4MaskLen=%d ipv4=%s resulted IPv6 address: %s", sixrdPrefixLen, ipv4MaskLen, ownIP.String(), myv6Addr)

	return myv6Addr, nil
}

func main() {
	log.SetFlags(log.Lshortfile)

	manualIP := flag.String("ip", "", "local ipv4 address")
	manualV6 := flag.String("prefix", "", "ipv6 network and prefix separated by /")
	manualMask := flag.Int("mask", 0, "ipv4 mask length")
	flag.Parse()

	if *manualIP != "" && *manualV6 != "" && *manualMask > 0 {
		v6Addr := netip.MustParsePrefix(*manualV6)
		ip, err := getIPv6Net(v6Addr.Addr(), netip.MustParseAddr(*manualIP), *manualMask, v6Addr.Bits())
		if err != nil {
			log.Printf("failed to build ipv6 address: %s", err)
			os.Exit(1)
		}
		log.Printf("build ipv6 address: %s", ip)
	}

	action := os.Getenv(EnvDispatcherAction)
	data := os.Getenv(EnvOption6rd)
	if len(data) > 0 && action == "up" {
		log.Printf("6rd option present, handling it")
		if err := handleEnvironment(data); err != nil {
			log.Printf("failed to bring ipv6 up: %s", err)
			os.Exit(1)
		}
		return
	}

	log.Printf("no 6rd dhcp option present in environment")

}

func handleEnvironment(data string) error {

	parts := strings.Split(data, " ")
	if len(parts) < 4 {
		log.Printf("could not parse %s", EnvOption6rd)
		os.Exit(1)
	}

	ownIP, err := netip.ParseAddr(os.Getenv(EnvOwnIP))
	if err != nil {
		return fmt.Errorf("failed to own address: %w", err)
	}

	log.Printf("own ip: %s", ownIP.String())

	v4Length, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("failed to parse dhcp option: %w", err)
	}
	v6Prefix, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("failed to parse dhcp option: %w", err)
	}
	prefix, err := netip.ParseAddr(parts[2])
	if err != nil {
		return fmt.Errorf("failed to parse dhcp option: %w", err)
	}
	relay, err := netip.ParseAddr(parts[3])
	if err != nil {
		return fmt.Errorf("failed to parse dhcp option: %w", err)
	}

	v6Addr, err := getIPv6Net(prefix, ownIP, v4Length, v6Prefix)
	if err != nil {
		return fmt.Errorf("failed to build v6 address: %w", err)
	}

	log.Printf("issuing iproute2 commands: tunnel delete, tunnel add, link up, addr add and route add")
	err1 := runCommand(IPRouteGroupTunnel, IPRouteOPDelete, deviceName6rd)
	err2 := runCommand(IPRouteGroupTunnel, IPRouteOPAdd, deviceName6rd, "mode", "sit", "local", ownIP.String(), "remote", relay.String(), "ttl", "64")
	err3 := runCommand(IPRouteGroupLink, IPRouteOPSet, deviceName6rd, "mtu", "1480", "up")
	err4 := runCommand(IPRouteGroupAddr, IPRouteOPAdd, v6Addr.String(), "dev", deviceName6rd)
	err5 := runCommand(IPRouteGroupRoute, IPRouteOPAdd, "default", "dev", deviceName6rd)

	return errors.Join(err1, err2, err3, err4, err5)
}

func runCommand(group iprouteGroup, op iprouteOP, args ...string) error {
	var cargs []string

	if group == IPRouteGroupRoute {
		cargs = append(cargs, "-6")
	}
	cargs = append(cargs, string(group), string(op))
	cargs = append(cargs, args...)

	cmdline := "/sbin/ip " + strings.Join(cargs, " ")
	log.Printf("running: %s", cmdline)

	c := exec.Command("/sbin/ip", cargs...)
	err := c.Run()
	if err != nil {
		log.Printf("command `%s` returned error: %s", cmdline, err)
	}

	if group == IPRouteGroupTunnel && op == IPRouteOPDelete {
		return nil
	}

	return err
}

func myIP() netip.Addr {
	resp, err := http.Get("https://ifconfig.co")
	if err != nil {
		log.Printf("failure to get my ip: %s", err)
	}
	defer resp.Body.Close()
	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failure to get my ip: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("got %d from ip address service", resp.StatusCode)
	}

	ips := string(bytes.TrimSpace(ip))
	log.Printf("my ip address: %s", ips)
	return netip.MustParseAddr(ips)
}
