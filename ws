#! /usr/bin/env bash

[ -t 0 ] && [ -z "$NOEVAL" ] && [ -n "$BASH_EXECUTION_STRING" ] && c="$BASH_EXECUTION_STRING" IFS="" NOEVAL=1 exec bash -c 'eval "$c"'

[[ -z "$NOCOLOR" ]] && {
    CY="\e[1;33m"
    CG="\e[1;32m"
    CR="\e[1;31m"
    CC="\e[1;36m"
    CW="\e[1;37m"
    CB="\e[1;34m"
    CF="\e[2m"
    CN="\e[0m"
    CDR="\e[0;31m"
    CDG="\e[0;32m"
    CDY="\e[0;33m"
    CDB="\e[0;34m"
    CDM="\e[0;35m"
    CDC="\e[0;36m"
    CUL="\e[4m"
}

addcn() {
    local IFS=" "
    local str="${1,,}"
    local regex="[^-a-z0-9.\*]"
    local tld
    str="${str//\"}"
    str="${str// }"
    str="${str//$'\r'}"
    [[ -z "$str" ]] && return
    tld="${str##*.}"
    [[ ${#tld} -le 1 ]] && return
    [[ "$str" != *"."* ]] && return
    [[ "$str" == *"@"* ]] && return
    [[ "$str" == *"example.org" ]] && return
    [[ "$str" == *"example.com" ]] && return
    [[ "$str" == "entrust.netsecureservercertificationauthority" ]] && return
    [[ "$str" == *".tld" ]] && return
    [[ "$str" == *".wtf" ]] && return
    [[ "$str" == *".if" ]] && return
    [[ "$str" == *"foo."* ]] && return
    [[ "$str" == *"localhost"* ]] && return
    [[ "$str" == *"domain.com" ]] && return
    [[ "$str" == *"domain1.com" ]] && return
    [[ "$str" == *"domain2.com" ]] && return
    [[ "$str" == *"site.com" ]] && return
    [[ "$str" == *".host.org" ]] && return
    [[ "$str" == *".nginx.org" ]] && return
    [[ "$str" == *"server-1.biz" ]] && return
    [[ "myforums.com headers.com isnot.org one.org two.org" == *"$str"* ]] && return
    [[ "$str" =~ $regex ]] && return
    [[ " ${arr[*]} " == *" $str "* ]] && return
    arr+=("$str")
}

addline() {
    local IFS
    local str="$1"
    local names
    local n
    IFS=$'\t'" " read -r -a names <<<"$str"
    for n in "${names[@]}"; do
        addcn "$n"
    done
}

addx509() {
    local x509="${1}"
    local str

    [[ "$(echo "$x509" | openssl x509 -noout -ext basicConstraints 2>/dev/null)" == *"CA:TRUE"* ]] && return

    str="$(echo "$x509" | openssl x509 -noout -subject 2>/dev/null)"
    [[ "$str" == "subject"* ]] && [[ "$str" == *"/CN"* ]] && {
        str="$(echo "$str" | sed '/^subject/s/^.*CN.*=[ ]*//g')"
        addcn "$str"
    }

    str="$(echo "$x509" | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -F DNS: | sed 's/\s*DNS://g' | sed 's/[^-a-z0-9\.\*,]//g')"
    addline "${str//,/$'\t'}"
}

addcertfn() {
    local fn="$1"
    [[ ! -f "$fn" ]] && return
    [[ "$fn" == *_csr-* ]] && return
    addx509 "$(<"${fn}")"
}

get_virt() {
    local str
    local cont
    local str_suffix
    local os
    local os_prefix

    if grep -sqF docker "/proc/1/cgroup" &>/dev/null || grep -F -m1 ' / / r' "/proc/self/mountinfo" | grep -sqF "docker"; then
        cont="Docker"
    elif tr '\000' '\n' <"/proc/1/environ" | grep -Eiq '^container=podman' || grep -sqF /libpod- "/proc/self/cgroup"; then
        cont="Podman"
    elif [[ -d /proc/vz ]]; then
        cont="Virtuozzo"
    elif tr '\000' '\n' <"/proc/1/environ" | grep -Eiq '^container=lxc'; then
        cont="LXC"
    elif [ -e /proc/cpuinfo ] && grep -q 'UML' "/proc/cpuinfo"; then
        cont="User Mode Linux"
    elif [[ "$(ls -di / | cut -f1 -d' ')" -gt 2 ]]; then
        cont="chroot"
    fi
    [[ -n "$cont" ]] && str_suffix="/${cont}"

    [[ -d /proc/bc ]] && { echo "OpenVZ${str_suffix}"; return; }

    str=$(uname -r)
    { [[ $str == *"microsoft"* ]] || [[ $str == *"WSL"* ]]; } && { echo "Microsoft WSL${str_suffix}"; return; }
    [[ $str == *"grsec"* ]] && { os="Linux-grsec"; os_prefix="${os}/"; }

    str="$(cat /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/board_vendor /sys/class/dmi/id/bios_vendor /sys/class/dmi/id/product_version 2>/dev/null)"
    [[ -n "$str" ]] && {
        [[ "$str" == *"VirtualBox"* ]]               && { echo "${os_prefix}VirtualBox${str_suffix}"; return; }
        [[ "$str" == *"innotek GmbH"* ]]             && { echo "${os_prefix}VirtualBox${str_suffix}"; return; }
        [[ "$str" == *"VMware"* ]]                   && { echo "${os_prefix}VMware${str_suffix}"; return; }
        [[ "$str" == *"KubeVirt"* ]]                 && { echo "${os_prefix}KubeVirt${str_suffix}"; return; }
        [[ "$str" == *"QEMU"* ]]                     && { echo "${os_prefix}QEMU${str_suffix}"; return; }
        [[ "$str" == *"OpenStack"* ]]                && { echo "${os_prefix}OpenStack${str_suffix}"; return; }
        [[ "$str" == *"Amazon "* ]]                  && { echo "${os_prefix}Amazon EC2${str_suffix}"; return; }
        [[ "$str" == *"KVM"* ]]                      && { echo "${os_prefix}KVM${str_suffix}"; return; }
        [[ "$str" == *"VMW"* ]]                      && { echo "${os_prefix}VMW${str_suffix}"; return; }
        [[ "$str" == *"Xen"* ]]                      && { echo "${os_prefix}Amazon Xen${str_suffix}"; return; }
        [[ "$str" == *"Bochs"* ]]                    && { echo "${os_prefix}Bochs${str_suffix}"; return; }
        [[ "$str" == *"Parallels"* ]]                && { echo "${os_prefix}Parallels${str_suffix}"; return; }
        [[ "$str" == *"BHYVE"* ]]                    && { echo "${os_prefix}BHYVE${str_suffix}"; return; }
        [[ "$str" == *"Hyper-V"* ]]                  && { echo "${os_prefix}Microsoft Hyper-V${str_suffix}"; return; }
        [[ "$str" == *"Virtual Machine"* ]] && [[ "$str" == *"Microsoft"* ]] && { echo "${os_prefix}Microsoft Hyper-V${str_suffix}"; return; }
        [[ "$str" == *"Apple Virtualization"* ]]     && { echo "${os_prefix}Apple Virtualization${str_suffix}"; return; }
    }

    [[ -n "$cont" ]] && { echo "${os}$cont"; return; }

    [[ -n "$os" ]] && { echo "${os}"; return; }

    return 255
}

HTTPS_curl() { curl -m 10 -fksSL "$*"; }
HTTPS_wget() { wget -qO- "--connect-timeout=7" "--dns-timeout=7" "--no-check-certificate" "$*"; }

COL_column() { column -t; }

if command -v curl >/dev/null; then
    HTTPS() { HTTPS_curl "$@"; }
elif command -v wget >/dev/null; then
    HTTPS() { HTTPS_wget "$@"; }
else
    HTTPS() { :; }
fi

if command -v column >/dev/null; then
    COL() { COL_column; }
else
    COL() { cat; }
fi

PATH="/usr/sbin:$PATH"
IFS=$'\n'
exec 2>&-

unset inet
command -v ip >/dev/null && inet="$(ip a show 2>/dev/null)"
[[ -z "$inet" ]] && command -v ifconfig >/dev/null && inet="$(ifconfig 2>/dev/null)"
[[ -n "$inet" ]] && inet=$(echo "$inet" | grep inet | grep -vF 'inet 127.' | grep -vF 'inet6 ::1' | awk '{print $2;}' | sort -rn)

echo -e "${CW}>>>>> 系统信息${CN}"
uname -a 2>/dev/null || cat /proc/version 2>/dev/null
str="$(get_virt)" && echo "虚拟化技术: $str"
ncpu=$(nproc 2>/dev/null)
[[ -e /proc/cpuinfo ]] && {
    [[ -z "$ncpu" ]] && ncpu=$(grep -c '^processor' /proc/cpuinfo)
    cpu=$(grep -m1 '^model name' /proc/cpuinfo | cut -f2 -d:)
    [[ -z "$cpu" ]] && cpu=$(grep -m1 '^cpu model' /proc/cpuinfo | cut -f2 -d:)
    [[ -z "$cpu" ]] && cpu=$(grep -m1 '^Hardware' /proc/cpuinfo | cut -f2 -d:)
}
[[ -z "$cpu" ]] && command -v sysctl >/dev/null && cpu=$(sysctl -a machdep.cpu.brand_string 2>/dev/null| head -n1 | grep '^machdep.cpu' | sed -e 's/[^:]*[: \t]*//')
[[ -z "$cpu" ]] && command -v lscpu >/dev/null && {
    cpu=$(lscpu 2>/dev/null | grep -m1 -F 'Model name:' | sed -e 's/[^:]*[: \t]*//')
    [[ -z "$cpu" ]] && cpu=$(lscpu 2>/dev/null | grep -m1 '^Vendor ID' | sed -e 's/[^:]*[: \t]*//')
}

command -v free >/dev/null && {
    mem=$(LANG=C free -h 2>/dev/null | grep -m1 ^Mem | awk '{print $2;}')
}
command -v top >/dev/null && [[ -z "$mem" ]] && {
    mem=$(top -l1 -s0 2>/dev/null | grep -m1 PhysMem | cut -f2- -d' ')
}
echo "CPU配置      : ${ncpu:-0}核${cpu:-???} / ${mem:-???} 内存"
unset mem cpu ncpu

hostnamectl 2>/dev/null || lsb_release -a 2>/dev/null
(source /etc/*release 2>/dev/null; [ -n "$PRETTY_NAME" ] && echo "系统名称: ${PRETTY_NAME}")
echo "日期时间   : $(date)"
command -v uptime >/dev/null && {
    str=$(uptime | sed -e 's/^[ \t]*//')
    [[ -n "$str" ]] && echo "运行时长   : $str"
}
id
ipinfo="$(HTTPS https://ipinfo.io 2>/dev/null)" && {
    ptrcn="${ipinfo#*  \"hostname\": \"}"
    ptrcn="${ptrcn%%\",*}"
    echo -e "$ipinfo"
}

[[ -n "$inet" ]] && {
    echo -e "${CY}>>>>> IP地址${CN}"
    echo "$inet"
}

unset arr
addcn "$ptrcn"
addcn "$(hostname 2>/dev/null)"

[[ -d /etc/nginx ]] && {
    lines=($(grep -r -E 'server_name .*;' /etc/nginx 2>/dev/null))
    for str in "${lines[@]}"; do
        str="${str#*server_name }"
        str="${str%;*}"
        addline "$str"
    done
}

[[ -d /etc/httpd ]] && {
    lines=($(grep -r -E ':*(ServerName|ServerAlias)[ ]+' /etc/httpd 2>/dev/null | grep -v ':[ ]*#'))
    for str in "${lines[@]}"; do
        str="${str#*ServerName }"
        str="${str#*ServerAlias }"
        addline "$str"
    done
}

unset certsfn
IFS=$'\n'
[[ -d /etc/nginx ]] && certsfn=($(find /etc/nginx -name '*.conf*' -exec grep -F "ssl_certificate " {} \; 2>/dev/null | awk '{print $NF;}' | sed 's/;$//' | sort -u))

certsfn+=($(find /etc -name '*.crt' -o -name '*.pem' 2>/dev/null))

for fn in "${certsfn[@]}"; do
    addcertfn "$fn"
done

addx509 "$(openssl s_client -showcerts -connect 0:443 2>/dev/null  </dev/null)"

IFS=$'\n' lines=($(grep -v '^#' /etc/hosts | grep -v -E '(^255\.|\sip6)'))
unset harr
IFS=$'\n'
for x in "${lines[@]}"; do
    [[ "${inet:-BLAHBLAHNOTEXIST} 127.0.0.1" == *"$(echo "$x" | awk '{print $1;}')"* ]] && {
        addline "$(echo "$x" | sed -E 's/[0-9.]+[ \t]+//')"
        continue
    }
    IFS=" "$'\t' harr+=($(echo "$x" | grep -vF localhost | sed -E 's/[0-9.]+[ \t]+//')) 
done
unset lines
unset IFS

[ "${#res[@]}" -eq 0 ] && [ -f ~/.msmtprc ] && {
    res="$(grep -im1 ^from ~/.msmtprc)"
    res="${res##*@}"
    [ -n "$res" ] && addcn "$res"
}

IFS=$'\n' res=($(printf "%s\n" "${arr[@]}" | sort -u))
unset arr
[[ ${#res[@]} -gt 0 ]] && {
    echo -e "${CY}>>>>> 域名列表${CN} (${#res[@]})"
    printf "域名 %s\n" "${res[@]}"
}

IFS=$'\n' res=($(printf "%s\n" "${harr[@]}" | sort -u))
unset harr
[[ ${#res[@]} -gt 0 ]] && {
    echo -e "${CY}>>>>> 其他主机 (来自 /etc/hosts)${CN} (${#res[@]})"
    printf "主机  %s\n" "${res[@]}" | sort -u
}
unset res

[[ -f ~/.ssh/known_hosts ]] && {
    echo -e "${CDM}>>>>> 最近SSH使用记录 (主机数: $(wc -l <~/.ssh/known_hosts))${CN}"
    command ls -ltu ~/.ssh/known_hosts
    IFS="" str="$(grep -v '^|' ~/.ssh/known_hosts | cut -f1 -d" " | cut -f1 -d, | uniq)"
    [[ -n "$str" ]] && echo -e "${CDM}>>>>> 已访问的SSH主机${CN}\n${str}"
}

echo -e "${CDM}>>>>> 存储信息 ${CN}"
df -h 2>/dev/null | grep -v ^tmpfs

echo -e "${CDM}>>>>> 历史命令记录${CN}"
ls -al ~/.*history* 2>/dev/null

echo -e "${CDM}>>>>> /home目录 (前20条)${CN}"
ls -Lld -t /root /home/* 2>/dev/null | head -n20

str=$(w -o -h 2>/dev/null | head -n100)
[[ -n "$str" ]] && {
    echo -e "${CDM}>>>>> 在线用户${CN}"
    echo "$str"
}

str=$(lastlog 2>/dev/null | tail -n+2 | grep -vF 'Never logged in')
[[ -n "$str" ]] && {
    echo -e "${CDM}>>>>> 登录记录${CN}"
    echo "$str"
}

echo -e "${CDM}>>>>> /root/目录${CN}"
ls -lat /root/ 2>/dev/null | head -n 100

if command -v ip >/dev/null; then
    echo -e "${CB}>>>>> 路由表${CN}"
    ip route show 2>/dev/null | COL
    echo -e "${CB}>>>>> 网络接口统计${CN}"
    { ip -s link || ip link show;} 2>/dev/null 
    echo -e "${CB}>>>>> ARP缓存${CN}"
    ip n sh 2>/dev/null | COL
else
    command -v netstat >/dev/null && {
        echo -e "${CB}>>>>> 路由表${CN}"
        netstat -rn 2>/dev/null
        echo -e "${CB}>>>>> 网络接口统计${CN}"
        netstat -in 2>/dev/null
    }
    echo -e "${CB}>>>>> ARP缓存${CN}"
    { arp -an | grep -iv 'incomplete' || cat /proc/net/arp || ip neigh show | grep -iv 'FAILED'; } 2>/dev/null | COL
fi

command -v netstat >/dev/null && {
    str=$(netstat -antp 2>/dev/null | grep LISTEN) || str=$(netstat -an 2>/dev/null | grep ^tcp | grep LISTEN | sort -u -k4 | sort -k1)
    [[ -n "$str" ]] && {
        echo -e "${CDG}>>>>> 监听的TCP端口${CN}"
        echo "$str"
    }
    str=$(netstat -anup 2>/dev/null | grep ^udp | grep -v ESTABL) || str=$(netstat -an 2>/dev/null | grep ^udp | grep -v ESTABL | grep -vF '0  *.*' | sort -u  -k4 |grep -E '\*\s*$')
    [[ -n "$str" ]] && {
        echo -e "${CDG}>>>>> 监听的UDP端口${CN}"
        echo "$str"
    }
}

[[ -n "$(docker ps -aq 2>/dev/null)" ]] && {
    echo -e "${CDR}>>>>> Docker容器${CN}"
    docker ps -a
}

echo -e "${CDR}>>>>> 进程列表${CN}"
HIDE_PPID=$PPID
[ "$HIDE_PPID" -eq 1 ] && HIDE_PPID=$$
{ ps --ppid 2,${HIDE_PPID:-0} -p 2,$$ --deselect flwww || ps alxwww || ps w;} 2>/dev/null | head -n 500

echo -e "${CW}>>>>> 扫描完成${CN}"

exit 0
