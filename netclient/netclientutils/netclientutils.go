package netclientutils

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const NO_DB_RECORD = "no result found"
const NO_DB_RECORDS = "could not find any records"
const WINDOWS_APP_DATA_PATH = "\\AppData\\Local\\Netclient"
const LINUX_APP_DATA_PATH = "/etc/netclient"
const WINDOWS_SVC_NAME = "Netclient"
const DEFAULT_MTU = 1280

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

func parsePeers(peers []wgtypes.PeerConfig) (string, error) {
	peersString := ""
	// PublicKey
	// AllowedIps
	// Enpoint publicip/localip:port
	// PersistentKeepAlive
	for _, peer := range peers {
		newAllowedIps := []string{}
		for _, allowedIP := range peer.AllowedIPs {
			newAllowedIps = append(newAllowedIps, allowedIP.String())
		}
		peersString += fmt.Sprintf(`[Peer]
PublicKey = %s
AllowedIps = %s
Endpoint = %s
PersistentKeepAlive = 20

`,
			peer.PublicKey.String(),
			strings.Join(newAllowedIps, ","),
			peer.Endpoint.String(),
		)
	}
	return peersString, nil
}

func CreateUserSpaceConf(address string, privatekey string, listenPort string, peers []wgtypes.PeerConfig) (string, error) {
	peersString, err := parsePeers(peers)
	listenPortString := ""
	if listenPort != "" {
		listenPortString += "ListenPort = " + listenPort
	}
	if err != nil {
		return "", err
	}
	config := fmt.Sprintf(`[Interface]
Address = %s
PrivateKey = %s
%s

%s

`,
		address+"/32",
		privatekey,
		listenPortString,
		peersString)
	return config, nil
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

// == OS PATH FUNCTIONS ==

func GetHomeDirWindows() string {
	if IsWindows() {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func GetNetclientPath() string {
	if IsWindows() {
		return GetHomeDirWindows() + WINDOWS_APP_DATA_PATH
	} else {
		return LINUX_APP_DATA_PATH
	}
}

func GetNetclientPathSpecific() string {
	if IsWindows() {
		return GetHomeDirWindows() + WINDOWS_APP_DATA_PATH + "\\"
	} else {
		return LINUX_APP_DATA_PATH + "/"
	}
}

// Implement later..
// func CreateWindowsService() (*mgr.Service, error) {
// 	m, err := mgr.Connect()
// 	if err != nil {
// 		return nil, errors.New("Netclient could not connect to Windows service manager")
// 	}

// 	windowsService, err := m.OpenService(WINDOWS_SVC_NAME)
// 	if err == nil {
// 		windowsService.Close()
// 		return nil, errors.New("service " + WINDOWS_SVC_NAME + " is already installed")
// 	}

// 	windowsExecutable, err := os.Executable()
// 	if err != nil {
// 		return nil, err
// 	}

// 	c := mgr.Config{
// 		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
// 		StartType:    mgr.StartAutomatic,
// 		ErrorControl: mgr.ErrorNormal,
// 		DisplayName:  WINDOWS_SVC_NAME,
// 		Description:  "Meshes Windows machine with Netmaker networks.",
// 	}

// 	windowsService, err = m.CreateService(WINDOWS_SVC_NAME, windowsExecutable, c)
// 	if err != nil {
// 		return nil, errors.New("failed to create Windows service " + WINDOWS_SVC_NAME)
// 	}
// 	defer windowsService.Close()

// 	recoveryActions := []mgr.RecoveryAction{
// 		{mgr.ServiceRestart, 1 * time.Second},
// 		{mgr.ServiceRestart, 8 * time.Second},
// 		{mgr.ServiceRestart, 16 * time.Second},
// 		{mgr.ServiceRestart, 24 * time.Second},
// 		{mgr.ServiceRestart, 32 * time.Second},
// 		{mgr.ServiceRestart, 40 * time.Second},
// 		{mgr.ServiceRestart, 48 * time.Second},
// 		{mgr.ServiceRestart, 56 * time.Second},
// 		{mgr.ServiceRestart, 64 * time.Second},
// 	}
// 	const resetPeriodSecs = 60
// 	err = windowsService.SetRecoveryActions(recoveryActions, resetPeriodSecs)
// 	if err != nil {
// 		return nil, errors.New("could not set recovery actions")
// 	}
// 	return windowsService, nil
// }
