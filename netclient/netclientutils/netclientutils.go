package netclientutils

import (
	"errors"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

const NO_DB_RECORD = "no result found"
const NO_DB_RECORDS = "could not find any records"
const WINDOWS_APP_DATA_PATH = "\\AppData\\Local\\Netclient"
const LINUX_APP_DATA_PATH = "/etc/netclient"

func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// == database returned nothing error ==
func IsEmptyRecord(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), NO_DB_RECORD) || strings.Contains(err.Error(), NO_DB_RECORDS)
}

//generate an access key value
func GenPass() string {

	var seededRand *rand.Rand = rand.New(
		rand.NewSource(time.Now().UnixNano()))

	length := 16
	charset := "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func GetPublicIP() (string, error) {

	iplist := []string{"http://ip.client.gravitl.com", "https://ifconfig.me", "http://api.ipify.org", "http://ipinfo.io/ip"}
	endpoint := ""
	var err error
	for _, ipserver := range iplist {
		resp, err := http.Get(ipserver)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			endpoint = string(bodyBytes)
			break
		}
	}
	if err == nil && endpoint == "" {
		err = errors.New("public address not found")
	}
	return endpoint, err
}

func GetMacAddr() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	return as, nil
}

func GetLocalIP(localrange string) (string, error) {
	_, localRange, err := net.ParseCIDR(localrange)
	if err != nil {
		return "", err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var local string
	found := false
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if i.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				if !found {
					ip = v.IP
					local = ip.String()
					found = localRange.Contains(ip)
				}
			case *net.IPAddr:
				if !found {
					ip = v.IP
					local = ip.String()
					found = localRange.Contains(ip)
				}
			}
		}
	}
	if !found || local == "" {
		return "", errors.New("Failed to find local IP in range " + localrange)
	}
	return local, nil
}

func GetFreePort(rangestart int32) (int32, error) {
	wgclient, err := wgctrl.New()
	if err != nil {
		return 0, err
	}
	devices, err := wgclient.Devices()
	if err != nil {
		return 0, err
	}
	var portno int32
	portno = 0
	for x := rangestart; x <= 60000; x++ {
		conflict := false
		for _, i := range devices {
			if int32(i.ListenPort) == x {
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		portno = x
		break
	}
	return portno, err
}

func GetNetclientPath() string {
	if IsWindows() {
		return WINDOWS_APP_DATA_PATH
	} else {
		return LINUX_APP_DATA_PATH
	}
}
