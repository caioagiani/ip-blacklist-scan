    <?php

    /** 
     * Author: Caio Agiani
     * Description: IP Blacklist abuse scan
     * Website: https://apility.io
     */

    extract($_GET);

    if (!isset($_GET['ip'])) die('Use: ' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] . '?ip=198.46.178.97');

    define('WEBSITE', 'https://api.apility.net/v2.0/ip/' . $ip . '?items=100'); // define default url api adress
    define('TOKEN', '56deba52-9052-4b99-a0fb-3df0dce54d57'); // set your toke account
    //743fbefa-3674-49d0-98b3-a3fffda60657

    if (!filter_var($ip, FILTER_VALIDATE_IP)) die('IP Adress invalid');

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

        function Color($hex, $text)
        {
            return '<font class="label label-danger" style="background-color:' . $hex . '">' . $text . '</font>';
        }
    }

    $open = new iPScan;
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

    if ($json['score'] !== 0) {
        $msg = '';

        foreach ($json as $key => $value) {
            $num = is_array($value) ? count($value) : 0;
        }

        foreach ($value as $key => $value) {
            $msg .= ' ' . $open->Color('#FF0000', $value);
        }

        echo $ip  . ' - was found in <b>' . $num . '</b> blacklist: <br />' . $msg;
    } else {
        echo $ip . ' - ' . $open->Color('#00FF00', 'not found') . ' blacklist';
    }

    if ($obj['fullip']['history']['score'] !== 0) {

        echo "<hr />IP address historic information: <br />";

        foreach ($obj['fullip']['history']['activity'] as $key => $value) {
            echo "<pre />";

            $cmd = $value['command'];
            $blacklist = $value['blacklists'] ? $value['blacklists'] : $value['blacklist_change']'';

            $final = str_replace('add', '<b>[+]</b> ' . $open->Color('#FF0000', 'IP was added to blacklist(s)'), $cmd . ' -> [' . $blacklist . ']');
            echo $final = str_replace('rem', '<b>[-]</b> ' . $open->Color('#00FF00', 'IP was removed from blacklist(s)'), $final) . '<br />';
        }
    } else {
        echo '<hr />IP address historic information: ' . $open->Color('#00FF00', '0');
    }
