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

/** remove duplicate vmess configs */
function remove_duplicate_vmess($input)
{
    $array = explode("\n", $input);
    $result = [];
    foreach ($array as $item) {
        $parts = decode_vmess($item);
        if ($parts !== null) {
            $part_ps = $parts["ps"];
            unset($parts["ps"]);
            if (count($parts) >= 3) {
                ksort($parts);
                $part_serialize = serialize($parts);
                $result[$part_serialize][] = $part_ps ?? "";
            }
        }
    }
    $finalResult = [];
    foreach ($result as $serial => $ps) {
        $partAfterHash = $ps[0] ?? "";
        $part_serialize = unserialize($serial);
        $part_serialize["ps"] = $partAfterHash;
        $finalResult[] = encode_vmess($part_serialize);
    }
    $output = "";
    foreach ($finalResult as $config) {
        $output .= $output == "" ? $config : "\n" . $config;
    }
    return $output;
}

/** Parse vless and trojan config*/
function parseProxyUrl($url, $type = "trojan")
{
    // Parse the URL into components
    $parsedUrl = parse_url($url);

    // Extract the parameters from the query string
    $params = [];
    if (isset($parsedUrl["query"])) {
        parse_str($parsedUrl["query"], $params);
    }

    // Construct the output object
    $output = [
        "protocol" => $type,
        "username" => isset($parsedUrl["user"]) ? $parsedUrl["user"] : "",
        "hostname" => isset($parsedUrl["host"]) ? $parsedUrl["host"] : "",
        "port" => isset($parsedUrl["port"]) ? $parsedUrl["port"] : "",
        "params" => $params,
        "hash" => isset($parsedUrl["fragment"]) ? $parsedUrl["fragment"] : "",
    ];

    return $output;
}

/** Build vless and trojan config*/
function buildProxyUrl($obj, $type = "trojan")
{
    $url = $type . "://";
    $url .= addUsernameAndPassword($obj);
    $url .= $obj["hostname"];
    $url .= addPort($obj);
    $url .= addParams($obj);
    $url .= addHash($obj);
    return $url;
}

function addUsernameAndPassword($obj)
{
    $url = "";
    if ($obj["username"] !== "") {
        $url .= $obj["username"];
        if (isset($obj["pass"]) && $obj["pass"] !== "") {
            $url .= ":" . $obj["pass"];
        }
        $url .= "@";
    }
    return $url;
}

function addPort($obj)
{
    $url = "";
    if (isset($obj["port"]) && $obj["port"] !== "") {
        $url .= ":" . $obj["port"];
    }
    return $url;
}

function addParams($obj)
{
    $url = "";
    if (!empty($obj["params"])) {
        $url .= "?" . http_build_query($obj["params"]);
    }
    return $url;
}

function addHash($obj)
{
    $url = "";
    if (isset($obj["hash"]) && $obj["hash"] !== "") {
        $url .= "#" . $obj["hash"];
    }
    return $url;
}

/** remove duplicate vless and trojan config*/
function remove_duplicate_xray($input, $type)
{
    $array = explode("\n", $input);
    $result = [];
    foreach ($array as $item) {
        $parts = parseProxyUrl($item, $type);
        $part_hash = $parts["hash"];
        unset($parts["hash"]);
        ksort($parts["params"]);
        $part_serialize = serialize($parts);
        $result[$part_serialize][] = $part_hash ?? "";
    }

    $finalResult = [];
    foreach ($result as $url => $parts) {
        $partAfterHash = $parts[0] ?? "";
        $part_serialize = unserialize($url);
        $part_serialize["hash"] = $partAfterHash;
        $finalResult[] = buildProxyUrl($part_serialize, $type);
    }

    $output = "";
    foreach ($finalResult as $config) {
        $output .= $output == "" ? $config : "\n" . $config;
    }
    return $output;
}

/** parse shadowsocks configs */
function ParseShadowsocks($config_str)
{
    // Parse the config string as a URL
    $url = parse_url($config_str);

    // Extract the encryption method and password from the user info
    list($encryption_method, $password) = explode(
        ":",
        base64_decode($url["user"])
    );

    // Extract the server address and port from the host and path
    $server_address = $url["host"];
    $server_port = $url["port"];

    // Extract the name from the fragment (if present)
    $name = isset($url["fragment"]) ? urldecode($url["fragment"]) : null;

    // Create an array to hold the server configuration
    $server = [
        "encryption_method" => $encryption_method,
        "password" => $password,
        "server_address" => $server_address,
        "server_port" => $server_port,
        "name" => $name,
    ];

    // Return the server configuration as a JSON string
    return $server;
}

/** build shadowsocks configs */
function BuildShadowsocks($server)
{
    // Encode the encryption method and password as a Base64-encoded string
    $user = base64_encode(
        $server["encryption_method"] . ":" . $server["password"]
    );

    // Construct the URL from the server address, port, and user info
    $url = "ss://$user@{$server["server_address"]}:{$server["server_port"]}";

    // If the name is present, add it as a fragment to the URL
    if (!empty($server["name"])) {
        $url .= "#" . urlencode($server["name"]);
    }

    // Return the URL as a string
    return $url;
}

/** remove duplicate shadowsocks configs */
function remove_duplicate_ss($input)
{
    $array = explode("\n", $input);
    $result = [];
    foreach ($array as $item) {
        $parts = ParseShadowsocks($item);
        $part_hash = $parts["name"];
        unset($parts["name"]);
        ksort($parts);
        $part_serialize = serialize($parts);
        $result[$part_serialize][] = $part_hash ?? "";
    }

    $finalResult = [];
    foreach ($result as $url => $parts) {
        $partAfterHash = $parts[0] ?? "";
        $part_serialize = unserialize($url);
        $part_serialize["name"] = $partAfterHash;
        $finalResult[] = BuildShadowsocks($part_serialize);
    }

    $output = "";
    foreach ($finalResult as $config) {
        $output .= $output == "" ? $config : "\n" . $config;
    }
    return $output;
}

/** Ping function optimized */
function ping($host, $timeout = 1)
{
    // Try to ping 1 time with timeout in seconds
    $cmd = "";

    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        // Windows
        $cmd = sprintf('ping -n 1 -w %d %s', $timeout * 1000, escapeshellarg($host));
    } else {
        // Linux/macOS
        $cmd = sprintf('ping -c 1 -W %d %s', $timeout, escapeshellarg($host));
    }

    exec($cmd, $output, $status);

    if ($status === 0) {
        // Check if output contains "time=" or "time<"
        foreach ($output as $line) {
            if (preg_match('/time[=<]\d+(\.\d+)?/', $line)) {
                return true;
            }
        }
    }

    return false;
}

/** Remove unavailable configs by ping test */
function remove_unavailable_configs($configs)
{
    $filtered = [];
    foreach ($configs as $config) {
        $type = detect_type($config);
        $parsed = parse_config($config);
        $host = "";

        switch ($type) {
            case "vmess":
                $host = $parsed["add"] ?? $parsed["hostname"] ?? "";
                break;
            case "vless":
            case "trojan":
                $host = $parsed["hostname"] ?? "";
                break;
            case "ss":
                $host = $parsed["server_address"] ?? "";
                break;
            default:
                $host = "";
        }

        if ($host !== "" && ping($host)) {
            $filtered[] = $config;
        }
        // else: حذف کانفیگ‌هایی که پینگ آنها ناموفق بوده
    }
    return $filtered;
}

// --------- نمونه استفاده ---------

$input = "vmess://...";  // رشته کانفیگ‌ها با جداکننده \n
$configs = explode("\n", trim($input));

// حذف کانفیگ‌های تکراری (مثال برای vmess)
$configs = array_unique($configs); // یا از توابع remove_duplicate_xray و ... استفاده کن

// حذف کانفیگ‌های unavailable
$configs = remove_unavailable_configs($configs);

// خروجی نهایی
$output = implode("\n", $configs);
echo $output;

?>
