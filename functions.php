<?php
/** Detect Type of Config */
function detect_type($input)
{
    $type = "";
    if (substr($input, 0, 8) === "vmess://") {
        $type = "vmess";
    } elseif (substr($input, 0, 8) === "vless://") {
        $type = "vless";
    } elseif (substr($input, 0, 9) === "trojan://") {
        $type = "trojan";
    } elseif (substr($input, 0, 5) === "ss://") {
        $type = "ss";
    }

    return $type;
}

function parse_config($input)
{
    $type = detect_type($input);
    $parsed_config = [];
    switch ($type) {
        case "vmess":
            $parsed_config = decode_vmess($input);
            break;
        case "vless":
        case "trojan":
            $parsed_config = parseProxyUrl($input, $type);
            break;
        case "ss":
            $parsed_config = ParseShadowsocks($input);
            break;
    }
    return $parsed_config;
}

function build_config($input, $type)
{
    $build_config = "";
    switch ($type) {
        case "vmess":
            $build_config = encode_vmess($input);
            break;
        case "vless":
        case "trojan":
            $build_config = buildProxyUrl($input, $type);
            break;
        case "ss":
            $build_config = BuildShadowsocks($input);
            break;
    }
    return $build_config;
}

/** parse vmess configs */
function decode_vmess($vmess_config)
{
    $vmess_data = substr($vmess_config, 8); // remove "vmess://"
    $decoded_data = json_decode(base64_decode($vmess_data), true);
    return $decoded_data;
}

/** build vmess configs */
function encode_vmess($config)
{
    $encoded_data = base64_encode(json_encode($config));
    $vmess_config = "vmess://" . $encoded_data;
    return $vmess_config;
}

/** Parse vless and trojan config*/
function parseProxyUrl($url, $type = "trojan")
{
    $url = str_replace($type . "://", "", $url);
    $url_parts = explode("?", $url);
    $proxy_info = explode("@", $url_parts[0]);
    $params = isset($url_parts[1]) ? $url_parts[1] : '';
    
    $result = [
        "network" => $type,
        "hostname" => $proxy_info[1],
        "port" => explode(":", $proxy_info[0])[1]
    ];

    if ($type === 'trojan') {
        $result['key'] = explode(":", $proxy_info[0])[0];
    } else {
        $result['hash'] = explode(":", $proxy_info[0])[0];
    }
    
    return $result;
}

/** remove duplicate vmess configs */
function remove_duplicate_vmess($input)
{
    $configs = explode("\n", $input);
    $unique_configs = array_unique($configs);
    return implode("\n", $unique_configs);
}

/** parse shadowsocks configs */
function ParseShadowsocks($config_str)
{
    $config_str = substr($config_str, 5); // remove "ss://"
    $data = explode(":", $config_str);
    return [
        "server_address" => $data[0],
        "server_port" => $data[1],
        "method" => $data[2],
        "password" => trim($data[3])
    ];
}

/** build shadowsocks configs */
function BuildShadowsocks($server)
{
    return "ss://" . $server['server_address'] . ":" . $server['server_port'] . ":" . $server['method'] . ":" . $server['password'];
}

/** remove duplicate shadowsocks configs */
function remove_duplicate_ss($input)
{
    $configs = explode("\n", $input);
    $unique_configs = array_unique($configs);
    return implode("\n", $unique_configs);
}

function is_ip($string)
{
    $ipv4_pattern = '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/';
    $ipv6_pattern = '/^[0-9a-fA-F:]+$/'; // matches any valid IPv6 address

    if (preg_match($ipv4_pattern, $string) || preg_match($ipv6_pattern, $string)) {
        return true;
    } else {
        return false;
    }
}

function ip_info($ip)
{
    if (is_ip($ip) === false) {
        $ip_address_array = dns_get_record($ip, DNS_A);
        if (is_array($ip_address_array)) {
            $randomKey = array_rand($ip_address_array);
            $ip = $ip_address_array[$randomKey]["ip"];
        }
    }
    $ipinfo = json_decode(
        file_get_contents("https://api.country.is/" . $ip),
        true
    );
    return $ipinfo;
}

function get_flag($ip)
{
    $flag = "";
    $ip_info = ip_info($ip);
    if (isset($ip_info["country"])) {
        $location = $ip_info["country"];
        $flag = $location . getFlags($location);
    } else {
        $flag = "R 🚩";
    }
    return $flag;
}

function getFlags($country_code)
{
    $flag = mb_convert_encoding(
        "&#" . (127397 + ord($country_code[0])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    $flag .= mb_convert_encoding(
        "&#" . (127397 + ord($country_code[1])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    return $flag;
}

function get_ip($config, $type)
{
    switch ($type) {
        case "vmess":
            return get_vmess_ip($config);
        case "vless":
            return get_vless_ip($config);
        case "trojan":
            return get_trojan_ip($config);
        case "ss":
            return get_ss_ip($config);
    }
}

function get_vmess_ip($input)
{
    return !empty($input["sni"])
        ? $input["sni"]
        : (!empty($input["host"])
            ? $input["host"]
            : $input["add"]);
}

function get_vless_ip($input)
{
    return !empty($input["host"])
        ? $input["host"]
        : $input["hostname"];
}

function get_trojan_ip($input)
{
    return !empty($input["params"]["sni"])
        ? $input["params"]["sni"]
        : (!empty($input["host"]) ? $input["host"] : $input["hostname"]);
}

function get_ss_ip($input)
{
    return $input["server_address"];
}

function get_port($input, $type)
{
    $port = "";
    switch ($type) {
        case "vmess":
            $port = $input["port"];
            break;
        case "vless":
            $port = $input["port"];
            break;
        case "trojan":
            $port = $input["port"];
            break;
        case "ss":
            $port = $input["server_port"];
            break;
    }
    return $port;
}

function ping($ip, $port)
{
    $it = microtime(true);
    $check = @fsockopen($ip, $port, $errno, $errstr, 0.5);
    $ft = microtime(true);
    $militime = round(($ft - $it) * 1e3, 2);
    if ($check) {
        fclose($check);
        return $militime;
    } else {
        return "unavailable";
    }
}

function generate_name($flag, $ip, $port, $ping)
{
    return $flag . " | " . $ip . ":" . $port . " | " . $ping . "ms";
}

function is_usa($ip) {
    $ip_info = ip_info($ip);
    return isset($ip_info["country"]) && $ip_info["country"] === "US";
}

function process_config($config)
{
    $name_array = [
        "vmess" => "ps",
        "vless" => "hash",
        "trojan" => "hash",
        "ss" => "name",
    ];
    $type = detect_type($config);
    $parsed_config = parse_config($config);
    $ip = get_ip($parsed_config, $type);
    $port = get_port($parsed_config, $type);
    $ping_data = ping($ip, $port);
    
    if ($ping_data !== "unavailable" && !is_usa($ip)) { // بررسی اینکه آیا IP آمریکا است
        $flag = get_flag($ip);
        $name_key = $name_array[$type];
        $parsed_config[$name_key] = generate_name($flag, $ip, $port, $ping_data);
        $final_config = build_config($parsed_config, $type);
        return $final_config;
    }
    return false;
}

/** Check if subscription is base64 encoded or not */
function is_base64_encoded($string)
{
    $decoded = base64_decode($string, true);
    return base64_encode($decoded) === $string;
}

function process_subscriptions($input)
{
    $output = [];
    if (is_base64_encoded($input)) {
        $data = base64_decode($input);
        $output = process_subscriptions_helper($data);
    } else {
        $output = process_subscriptions_helper($input);
    }
    return $output;
}

function process_subscriptions_helper($input) {
    $output = [];
    $data_array = explode("\n", $input);
    foreach ($data_array as $config) {
        $processed_config = process_config($config);
        if ($processed_config !== false) {
            $type = detect_type($processed_config);
            switch ($type) {
                case "vmess":
                    $output["vmess"][] = $processed_config;
                    break;
                case "vless":
                    $output["vless"][] = $processed_config;
                    break;
                case "trojan":
                    $output["trojan"][] = $processed_config;
                    break;
                case "ss":
                    $output["ss"][] = $processed_config;
                    break;
            }
        }
    }
    return $output;
}

function merge_subscription($input)
{
    $output = [];
    $vmess = "";
    $vless = "";
    $trojan = "";
    $shadowsocks = "";
    foreach ($input as $subscription_url) {
        $subscription_data = file_get_contents($subscription_url);
        $processed_array = process_subscriptions($subscription_data);
        $vmess .= isset($processed_array["vmess"])
            ? implode("\n", $processed_array["vmess"]) . "\n"
            : "";
        $vless .= isset($processed_array["vless"])
            ? implode("\n", $processed_array["vless"]) . "\n"
            : "";
        $trojan .= isset($processed_array["trojan"])
            ? implode("\n", $processed_array["trojan"]) . "\n"
            : "";
        $shadowsocks .= isset($processed_array["ss"])
            ? implode("\n", $processed_array["ss"]) . "\n"
            : "";
    }
    $output['vmess'] = explode("\n", trim($vmess));
    $output['vless'] = explode("\n", trim($vless));
    $output['trojan'] = explode("\n", trim($trojan));
    $output['ss'] = explode("\n", trim($shadowsocks));
    return $output;
}

function array_to_subscription($input) {
    return implode("\n", $input);
}
