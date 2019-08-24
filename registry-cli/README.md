# a convilent cmd registry client

## usage

### list repositories

`registry-cli -r <registry-addr> -u <username>:<password> repo list`

#### list repositories by namespace

`registry-cli get repo -n library`

### list repo tags

`registry-cli -r <registry-addr> tag list <repo>`

### get tag manifests

`registry-cli -r <registry-addr> tag mf <repo>:<tag>`

get manifests V1

`registry-cli -r <registry-addr> tag mf <repo>:<tag> -s v1`

### delete tag

`registry-cli -r <registry-addr> tag delete <repo>:<tag>`

### copy tag

`registry-cli -r <registry-addr> tag cp <src-repo>:<src-tag> <dst-repo>:<dst-tag>`

## example

`registry-cli -r 192.168.1.102 -u admin:admin repo list`

## design

if no `-u` set, registry-cli will try to get registry account from ~/.docker/config.json


## build

`GOOS=linux GOARCH=amd64 go build -o registry-cli main.go`
