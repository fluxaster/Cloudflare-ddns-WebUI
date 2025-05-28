# 获取本地所有IPv6地址（排除临时地址和本地回环地址）
$ipv6Addresses = Get-NetIPAddress -AddressFamily IPv6 `
    | Where-Object {
        $_.PrefixOrigin -eq 'Dhcp' -or $_.PrefixOrigin -eq 'RouterAdvertisement' # 这两个条件通常意味着地址是由网络分配的
    } `
    | Where-Object {
        # SkipAsSource 通常可以用于识别临时地址，但并非绝对，不同Windows版本和配置下行为可能略有差异
        # $_.SkipAsSource -eq $false -and # 如果希望更严格排除临时地址，可以考虑加回来，但要测试
        $_.AddressState -eq 'Preferred' -and
        $_.IPAddress -notlike 'fe80*' -and # 排除本地链路地址
        $_.IPAddress -ne '::1' # 排除环回地址
    } `
    | Select-Object -ExpandProperty IPAddress

# 输出所有找到的公网IPv6地址
$ipv6Addresses
