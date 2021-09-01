package functions

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"strings"

	nodepb "github.com/gravitl/netmaker/grpc"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/netclient/auth"
	"github.com/gravitl/netmaker/netclient/config"
	"github.com/gravitl/netmaker/netclient/local"
	"github.com/gravitl/netmaker/netclient/netclientutils"
	"golang.zx2c4.com/wireguard/wgctrl"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	//homedir "github.com/mitchellh/go-homedir"
)

var (
	wcclient nodepb.NodeServiceClient
)

func ListPorts() error {
	wgclient, err := wgctrl.New()
	if err != nil {
		return err
	}
	devices, err := wgclient.Devices()
	if err != nil {
		return err
	}
	fmt.Println("Here are your ports:")
	for _, i := range devices {
		fmt.Println(i.ListenPort)
	}
	return err
}

func getPrivateAddr() (string, error) {
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
					found = true
				}
			case *net.IPAddr:
				if !found {
					ip = v.IP
					local = ip.String()
					found = true
				}
			}
		}
	}
	if !found {
		err := errors.New("Local Address Not Found.")
		return "", err
	}
	return local, err
}

func needInterfaceUpdate(ctx context.Context, mac string, network string, iface string) (bool, string, error) {
	var header metadata.MD
	req := &nodepb.Object{
		Data: mac + "###" + network,
		Type: nodepb.STRING_TYPE,
	}
	readres, err := wcclient.ReadNode(ctx, req, grpc.Header(&header))
	if err != nil {
		return false, "", err
		log.Fatalf("Error: %v", err)
	}
	var resNode models.Node
	if err := json.Unmarshal([]byte(readres.Data), &resNode); err != nil {
		return false, iface, err
	}
	oldiface := resNode.Interface

	return iface != oldiface, oldiface, err
}

func GetNode(network string) models.Node {

	modcfg, err := config.ReadConfig(network)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	return modcfg.Node
}

func Uninstall() error {
	networks, err := GetNetworks()
	if err != nil {
		log.Println("unable to retrieve networks: ", err)
		log.Println("continuing uninstall without leaving networks")
	} else {
		for _, network := range networks {
			err = LeaveNetwork(network)
			if err != nil {
				log.Println("Encounter issue leaving network "+network+": ", err)
			}
		}
	}
	return err
}

func LeaveNetwork(network string) error {
	//need to  implement checkin on server side
	cfg, err := config.ReadConfig(network)
	if err != nil {
		return err
	}
	servercfg := cfg.Server
	node := cfg.Node

	var wcclient nodepb.NodeServiceClient
	var requestOpts grpc.DialOption
	requestOpts = grpc.WithInsecure()
	if cfg.Server.GRPCSSL == "on" {
		h2creds := credentials.NewTLS(&tls.Config{NextProtos: []string{"h2"}})
		requestOpts = grpc.WithTransportCredentials(h2creds)
	}
	conn, err := grpc.Dial(servercfg.GRPCAddress, requestOpts)
	if err != nil {
		log.Printf("Unable to establish client connection to "+servercfg.GRPCAddress+": %v", err)
	} else {
		wcclient = nodepb.NewNodeServiceClient(conn)

		ctx := context.Background()
		ctx, err = auth.SetJWT(wcclient, network)
		if err != nil {
			log.Printf("Failed to authenticate: %v", err)
		} else {
			node.SetID()
			var header metadata.MD
			_, err = wcclient.DeleteNode(
				ctx,
				&nodepb.Object{
					Data: node.ID,
					Type: nodepb.STRING_TYPE,
				},
				grpc.Header(&header),
			)
			if err != nil {
				log.Printf("Encountered error deleting node: %v", err)
				log.Println(err)
			} else {
				log.Println("Removed machine from " + node.Network + " network on remote server")
			}
		}
	}
	return RemoveLocalInstance(cfg, network)
}

func RemoveLocalInstance(cfg *config.ClientConfig, networkName string) error {
	err := local.WipeLocal(networkName)
	if err != nil {
		log.Printf("Unable to wipe local config: %v", err)
	} else {
		log.Println("Removed " + networkName + " network locally")
	}
	if cfg.Daemon != "off" {
		if netclientutils.IsWindows() {
			// TODO: Remove job?
		} else {
			err = local.RemoveSystemDServices(networkName)
		}
	}
	return err
}

func DeleteInterface(ifacename string, postdown string) error {
	ipExec, err := exec.LookPath("ip")
	if err != nil {
		log.Println(err)
	}
	out, err := local.RunCmd(ipExec + " link del " + ifacename)
	if err != nil {
		log.Println(out, err)
	}
	if postdown != "" {
		runcmds := strings.Split(postdown, "; ")
		err = local.RunCmds(runcmds)
		if err != nil {
			log.Println("Error encountered running PostDown: " + err.Error())
		}
	}
	return err
}

func List() error {

	networks, err := GetNetworks()
	if err != nil {
		return err
	}
	for _, network := range networks {
		cfg, err := config.ReadConfig(network)
		if err == nil {
			jsoncfg, _ := json.Marshal(
				map[string]string{
					"Name":           cfg.Node.Name,
					"Interface":      cfg.Node.Interface,
					"PrivateIPv4":    cfg.Node.Address,
					"PrivateIPv6":    cfg.Node.Address6,
					"PublicEndpoint": cfg.Node.Endpoint,
				})
			log.Println(network + ": " + string(jsoncfg))
		} else {
			log.Println(network + ": Could not retrieve network configuration.")
		}
	}
	return nil
}

func GetNetworks() ([]string, error) {
	var networks []string
	files, err := ioutil.ReadDir(netclientutils.GetNetclientPath())
	if err != nil {
		return networks, err
	}
	for _, f := range files {
		if strings.Contains(f.Name(), "netconfig-") {
			networkname := stringAfter(f.Name(), "netconfig-")
			networks = append(networks, networkname)
		}
	}
	return networks, err
}

func stringAfter(original string, substring string) string {
	position := strings.LastIndex(original, substring)
	if position == -1 {
		return ""
	}
	adjustedPosition := position + len(substring)

	if adjustedPosition >= len(original) {
		return ""
	}
	return original[adjustedPosition:len(original)]
}
