package local

import (
	"strings"

	"github.com/gravitl/netmaker/netclient/netclientutils"
)

// == Windows specific locals ==
func IsWindowsWGInstalled() bool {
	out, err := RunCmd("wg help")
	if err != nil {
		return false
	}
	return strings.Contains(out, "Available subcommand")
}

func ApplyWindowsConf(confPath string) error {
	if _, err := RunCmd("wireguard.exe /installtunnelservice " + confPath); err != nil {
		return err
	}
	return nil
}

func RemoveWindowsConf(ifacename string) error {
	if _, err := RunCmd("wireguard.exe /uninstalltunnelservice " + ifacename); err != nil {
		return err
	}
	return nil
}

func StartWindowsDaemon() error {
	_, err := RunCmd("sc create netclient binPath= \"" + netclientutils.GetNetclientPathSpecific() + "netclient.exe" + "\" start= auto")
	return err
}

// == end Windows specific locals ==
