printf '%s\n' "$metadata" | awk '
  /^[^\t]/ && $NF == "go@GO_VERSION@" { compiler=1 }
  $1 == "path" && $2 == "github.com/amnezia-vpn/amneziawg-go/v3" { module=1 }
  $1 == "build" && $2 == "vcs.revision=@ENGINE_REV@" { revision=1 }
  $1 == "dep" && $2 == "golang.org/x/crypto" && $3 == "@CRYPTO_VERSION@" { crypto=1 }
  $1 == "dep" && $2 == "golang.org/x/net" && $3 == "@NET_VERSION@" { network=1 }
  $1 == "dep" && $2 == "golang.org/x/sys" && $3 == "@SYS_VERSION@" { systemdep=1 }
  $1 == "=>" { replaced=1 }
  END { exit !(compiler && module && revision && crypto && network && systemdep && !replaced) }
'
