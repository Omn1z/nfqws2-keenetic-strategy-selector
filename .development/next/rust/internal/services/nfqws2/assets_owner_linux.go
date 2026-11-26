//go:build linux

package nfqws2

import (
	"io/fs"
	"os"
	"syscall"

	routerpath "nfqws2strategy/internal/tools/path"
)

func preserveAssetOwner(st fs.FileInfo, target *os.File) error {
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	current, err := target.Stat()
	if err != nil {
		return err
	}
	if now, ok := current.Sys().(*syscall.Stat_t); ok && now.Uid == owner.Uid && now.Gid == owner.Gid {
		return nil
	}
	return target.Chown(int(owner.Uid), int(owner.Gid))
}

func initializeAssetOwner(target *os.File, owner *assetOwner) error {
	st, err := target.Stat()
	if err != nil {
		return err
	}
	if now, ok := st.Sys().(*syscall.Stat_t); ok && int(now.Uid) == owner.uid && int(now.Gid) == owner.gid {
		return nil
	}
	return target.Chown(owner.uid, owner.gid)
}

func newAutolistOwner(conf []byte) (*assetOwner, error) {
	user, err := engineUserLiteral(conf)
	if err != nil {
		return nil, err
	}
	return lookupAssetOwner(user, []string{routerpath.Path(routerpath.AuthEtcDir, "passwd"), routerpath.Path(routerpath.EtcDir, "passwd")})
}
