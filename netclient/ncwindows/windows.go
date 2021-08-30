package ncwindows

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"

	nodepb "github.com/gravitl/netmaker/grpc"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/netclient/auth"
	"github.com/gravitl/netmaker/netclient/config"
	"github.com/gravitl/netmaker/netclient/local"
	"github.com/gravitl/netmaker/netclient/netclientutils"
	"github.com/gravitl/netmaker/netclient/server"
	"github.com/gravitl/netmaker/netclient/wireguard"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// == BEGIN WINDOWS UTIL FUNCTIONS ==
func amAdminWindows() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

func GetHomeDirWindows() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func GetDataDirectoryWindows() string {
	return GetHomeDirWindows() + netclientutils.WINDOWS_APP_DATA_PATH
}

func runMeElevated() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		log.Fatal("please run netclient as an admin user")
	}
}

// == END WINDOWS UTIL FUNCTIONS ==

// Initialize windows directory & files and such
func InitWindows() {
	if !amAdminWindows() { // first check if user is a Windows admin
		runMeElevated()
	}

	_, directoryErr := os.Stat(GetDataDirectoryWindows()) // Check if data directory exists or not
	if os.IsNotExist(directoryErr) {                      // create a data directory
		os.Mkdir(GetDataDirectoryWindows(), 0755)
	}
	wdPath, wdErr := os.Getwd() // get the current working directory
	if wdErr != nil {
		log.Fatal("failed to get current directory..")
	}
	_, dataNetclientErr := os.Stat(GetDataDirectoryWindows() + "\\netclient.exe")
	_, currentNetclientErr := os.Stat(wdPath + "\\netclient.exe")
	if os.IsNotExist(dataNetclientErr) { // check and see if netclient.exe is in appdata
		if currentNetclientErr == nil { // copy it if it exists locally
			input, err := ioutil.ReadFile(wdPath + "\\netclient.exe")
			if err != nil {
				log.Println("failed to find netclient.exe")
			}
			if err = ioutil.WriteFile(GetDataDirectoryWindows()+"\\netclient.exe", input, 0644); err != nil {
				log.Println("failed to copy netclient.exe to", netclientutils.WINDOWS_APP_DATA_PATH)
			}
		}
	}

	log.Println("successfully initialized Windows Netclient, happy meshing!")
}

/**
 *	Join command for windows client
 */
func WindowsJoin(cfg config.ClientConfig, privateKey string) error {

	hasnet := local.HasNetwork(cfg.Network)
	if hasnet {
		err := errors.New("ALREADY_INSTALLED. Netclient appears to already be installed for " + cfg.Network + ". To re-install, please remove by executing 'sudo netclient leave -n " + cfg.Network + "'. Then re-run the install command.")
		return err
	}
	log.Println("attempting to join " + cfg.Network + " at " + cfg.Server.GRPCAddress)
	err := config.Write(&cfg, cfg.Network)
	if err != nil {
		return err
	}

	wgclient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgclient.Close()
	if cfg.Node.Network == "" {
		return errors.New("no network provided")
	}
	if cfg.Node.LocalRange != "" {
		if cfg.Node.LocalAddress == "" {
			log.Println("local vpn, getting local address from range: " + cfg.Node.LocalRange)
			ifaces, err := net.Interfaces()
			if err != nil {
				return err
			}
			_, localrange, err := net.ParseCIDR(cfg.Node.LocalRange)
			if err != nil {
				return err
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
					return err
				}
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						if !found {
							ip = v.IP
							local = ip.String()
							if cfg.Node.IsLocal == "yes" {
								found = localrange.Contains(ip)
							} else {
								found = true
							}
						}
					case *net.IPAddr:
						if !found {
							ip = v.IP
							local = ip.String()
							if cfg.Node.IsLocal == "yes" {
								found = localrange.Contains(ip)

							} else {
								found = true
							}
						}
					}
				}
			}
			cfg.Node.LocalAddress = local
		}
	}
	if cfg.Node.Password == "" {
		cfg.Node.Password = netclientutils.GenPass()
	}
	auth.StoreSecret(cfg.Node.Password, cfg.Node.Network)
	if cfg.Node.Endpoint == "" {
		if cfg.Node.IsLocal == "yes" && cfg.Node.LocalAddress != "" {
			cfg.Node.Endpoint = cfg.Node.LocalAddress
		} else {
			cfg.Node.Endpoint, err = netclientutils.GetPublicIP()
			if err != nil {
				fmt.Println("Error setting cfg.Node.Endpoint.")
				return err
			}
		}
	}
	if privateKey == "" {
		wgPrivatekey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Fatal(err)
		}
		privateKey = wgPrivatekey.String()
		cfg.Node.PublicKey = wgPrivatekey.PublicKey().String()
	}

	if cfg.Node.MacAddress == "" {
		macs, err := netclientutils.GetMacAddr()
		if err != nil {
			return err
		} else if len(macs) == 0 {
			log.Fatal()
		} else {
			cfg.Node.MacAddress = macs[0]
		}
	}

	var wcclient nodepb.NodeServiceClient
	var requestOpts grpc.DialOption
	requestOpts = grpc.WithInsecure()
	if cfg.Server.GRPCSSL == "on" {
		h2creds := credentials.NewTLS(&tls.Config{NextProtos: []string{"h2"}})
		requestOpts = grpc.WithTransportCredentials(h2creds)
	}
	conn, err := grpc.Dial(cfg.Server.GRPCAddress, requestOpts)

	if err != nil {
		log.Fatalf("Unable to establish client connection to "+cfg.Server.GRPCAddress+": %v", err)
	}

	wcclient = nodepb.NewNodeServiceClient(conn)

	postnode := &models.Node{
		Password:            cfg.Node.Password,
		MacAddress:          cfg.Node.MacAddress,
		AccessKey:           cfg.Server.AccessKey,
		Network:             cfg.Network,
		ListenPort:          cfg.Node.ListenPort,
		PostUp:              cfg.Node.PostUp,
		PostDown:            cfg.Node.PostDown,
		PersistentKeepalive: cfg.Node.PersistentKeepalive,
		LocalAddress:        cfg.Node.LocalAddress,
		Interface:           cfg.Node.Interface,
		PublicKey:           cfg.Node.PublicKey,
		Name:                cfg.Node.Name,
		Endpoint:            cfg.Node.Endpoint,
		SaveConfig:          cfg.Node.SaveConfig,
		UDPHolePunch:        cfg.Node.UDPHolePunch,
	}

	if err = config.ModConfig(postnode); err != nil {
		return err
	}
	data, err := json.Marshal(postnode)
	if err != nil {
		return err
	}

	res, err := wcclient.CreateNode(
		context.TODO(),
		&nodepb.Object{
			Data: string(data),
			Type: nodepb.NODE_TYPE,
		},
	)
	if err != nil {
		return err
	}
	log.Println("node created on remote server...updating configs")

	nodeData := res.Data
	var node models.Node
	if err = json.Unmarshal([]byte(nodeData), &node); err != nil {
		return err
	}

	if node.ListenPort == 0 {
		node.ListenPort, err = netclientutils.GetFreePort(51821)
		if err != nil {
			fmt.Printf("Error retrieving port: %v", err)
		}
	}

	if node.DNSOn == "yes" {
		cfg.Node.DNSOn = "yes"
	}
	if !(cfg.Node.IsLocal == "yes") && node.IsLocal == "yes" && node.LocalRange != "" {
		node.LocalAddress, err = netclientutils.GetLocalIP(node.LocalRange)
		if err != nil {
			return err
		}
		node.Endpoint = node.LocalAddress
	}
	err = config.ModConfig(&node)
	if err != nil {
		return err
	}

	err = wireguard.StorePrivKey(privateKey, cfg.Network)
	if err != nil {
		return err
	}

	if node.IsPending == "yes" {
		fmt.Println("Node is marked as PENDING.")
		fmt.Println("Awaiting approval from Admin before configuring WireGuard.")
		if cfg.Daemon != "off" {
			// TODO: configure windows job
			return err
		}
	}
	log.Println("retrieving remote peers")
	peers, hasGateway, gateways, err := server.GetPeers(node.MacAddress, cfg.Network, cfg.Server.GRPCAddress, node.IsDualStack == "yes", node.IsIngressGateway == "yes")

	if err != nil && !netclientutils.IsEmptyRecord(err) {
		log.Println("failed to retrieve peers", err)
		return err
	}

	log.Println("starting wireguard")
	err = wireguard.InitWireguard(&node, privateKey, peers, hasGateway, gateways)
	if err != nil {
		return err
	}
	if cfg.Daemon != "off" { // TODO: use a windows job
	}
	if err != nil {
		return err
	}

	return err
}

/**
 * Leave command for windows client
 */
func WindowsLeave() error {

	return nil
}

/**
 *	Check config/in function for windows client
 */
func WindowsCheckConfig() error {

	return nil
}
