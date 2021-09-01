package netclientutils

import (
	"net"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var wgInterface tun.Device

// Creates a new userspace - Wireguard interface
// used for Windows and Mac (future) Netclients
func CreateWGUserspace(interfaceName string, address string) error {
	var err error
	wgInterface, err = tun.CreateTUN(interfaceName, DEFAULT_MTU)
	if err != nil {
		return err
	}

	wgDevice := device.NewDevice(wgInterface, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "Netclient: "))
	if err = wgDevice.Up(); err != nil {
		return err
	}

	uapiListener, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		return err
	}

	go func() {
		for {
			if conn, err := uapiListener.Accept(); err == nil {
				go wgDevice.IpcHandle(conn)
			}
		}
	}()

	return assignAddressToInterface(address, interfaceName)
}

func assignAddressToInterface(address string, interfaceName string) error {

	nativeTunDevice := wgInterface.(*tun.NativeTun)
	luid := winipcfg.LUID(nativeTunDevice.LUID())

	ip, ipnet, _ := net.ParseCIDR(address)

	if err := luid.SetIPAddresses([]net.IPNet{{ip, ipnet.Mask}}); err != nil {
		return err
	}

	if err := luid.SetRoutes([]*winipcfg.RouteData{{*ipnet, ipnet.IP, 0}}); err != nil {
		return err
	}
	return nil
}

// Closes the tunnel interface
func Close() error {
	return wgInterface.Close()
}
