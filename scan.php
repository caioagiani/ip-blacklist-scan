<?php

/** 
 * Author: Caio Agiani
 * Description: IP Blacklist abuse scan
 * Website: https://apility.io
 */

extract($_GET);

if (!isset($_GET['ip'])) die(json_encode((array('status' => false, 'return' => $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] . '?ip=198.46.178.97'))));

define('WEBSITE', 'https://api.apility.net/v2.0/ip/' . $ip . '?items=100'); // define default url api adress
define('TOKEN', '56deba52-9052-4b99-a0fb-3df0dce54d57'); // set your token account { 743fbefa-3674-49d0-98b3-a3fffda60657 } 

if (!filter_var($ip, FILTER_VALIDATE_IP)) die(json_encode(array('status' => false, 'return' => 'IP address invalid')));

class iPScan
{
    static function Acces($url, $post = false, $header = array(''))
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
        curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

        if ($post) curl_setopt($ch, CURLOPT_POSTFIELDS, $post);

        $data = curl_exec($ch);
        curl_close($ch);

        return $data;
    }
}

$open = new iPScan();

$url = $open::Acces(
    WEBSITE,
    false,
    array(
        'Content-Type: application/json',
        'X-Auth-Token: ' . TOKEN
    )
);

$obj = json_decode($url, true);

$json = $obj['fullip']['badip'];

if (!is_array($json)) die(json_encode(array('status' => false, 'return' => TOKEN . ' invalid token.')));

if ($json['score'] === 0) die(json_encode(array('status' => true, 'return' => $ip . ' not found blacklist hole')));

foreach ($json as $key => $value) 
{
    $num = is_array($value) ? count($value) : 0;
}

$dados = [];

foreach ($obj['fullip']['history']['activity'] as $key => $value) 
{
    array_push($dados, $value);
}

echo json_encode(array('status' => true, $ip  . ' - was found in ' . $num . ' blacklist', 'info' => $dados));
