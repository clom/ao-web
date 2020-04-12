<?php

namespace App\Http\Controllers;

use Exception;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Laravel\Lumen\Routing\Controller as BaseController;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use Ramsey\Uuid\Uuid;

class Controller extends BaseController
{

    private $token_validation_link = 'https://appleid.apple.com/auth/token';
    private $get_public_key_link = 'https://appleid.apple.com/auth/keys';

    public function login(){
        $uuid = Uuid::uuid4();
        $params = array(
            'client_id' => env('CLIENT_ID', 'client_id'),
            'redirect_uri' => env('REDIRECT_URL', 'callback'),
            'response_type' => 'code id_token',
            'response_mode' => 'form_post',
            'state' => $uuid->toString()
        );
        
        return view('index', $params);
    }

    public function callback(Request $req){
        $request = $req->all();
        $id_token = $this->verify_token($request['code']);
        if(empty($id_token)) {
            return view('callback', ['data' => 'empty id token']);
        }

        $jwt = $this->decode_user_token($id_token);

        if (empty($jwt)) {
            return view('callback', ['data' => 'empty JWT']);
        }

        return view('callback', ['data' => (Array)$jwt]);
    }

    private function verify_token($code){
        try {
            $params = array(
                'code' => $code,
                'grant_type' => 'authorization_code',
                'redirect_uri'	=>  env('REDIRECT_URL', 'callback'),
                'client_id' => env('CLIENT_ID', 'client_id'),
                'client_secret' => $this->create_client_secret()
            );

            $data = http_build_query($params);

            $header = array(
                "Content-Type: application/x-www-form-urlencoded",
                "Content-Length: ".strlen($data),
                "User-Agent: ao.clom.dev"
            );

            $curl = curl_init();
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_URL, $this->token_validation_link);
            curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
            curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
            curl_setopt($curl, CURLOPT_TIMEOUT, 5);

            $result = curl_exec($curl);
            $response = json_decode($result, true);
            $status_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            //curl_close($curl);

            if ($status_code !== 200) {
                Log::info(curl_error($curl));
                return FALSE;
            }

            return $response['id_token'];
        } catch (Exception $e) {
            Log::info($e->getMessage());
            return FALSE;
        }
    }

    private function create_client_secret()
    {
        $key = file_get_contents(env('PRIVATE_KET_PASS', 'null'));
        $now = time();
        $expire = $now + (7 * 24 * 60 * 60);

        $payload = array(
            'iss' => env('TEAM_ID', 'team_id'),
            'iat' => $now,
            'exp' => $expire,
            'aud' => 'https://appleid.apple.com',
            'sub' =>  env('SERVICE_ID', 'service_id')
        );

        return JWT::encode($payload, $key, 'ES256', env('KEY_ID', 'key_id'));
    }

    private function decode_user_token($jwt_token)
    {
        $curl = curl_init($this->get_public_key_link);

        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'GET'); 
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($curl);
        $info = curl_getinfo($curl);
        curl_close($curl);

        if ($info['http_code'] != 200) {
            return null;
        }
        $response = json_decode($response, true);
        $public_keys = $response['keys'];

        if ($public_keys === null) {
            return null;
        }

        $last_key = end($public_keys);
        foreach($public_keys as $data) {
            try {
                // decode action
                $public_key = $this->create_jwk_public_key($data);
                $token = JWT::decode($jwt_token, $public_key, array('RS256'));
                break;
            } catch (Exception $e) {
                if($data === $last_key) {
                    return null;
                }
            }
        }

        return $token;
    }

    private function create_jwk_public_key($jwk)
    {
        $rsa = new RSA();
        $rsa->loadKey(
            [
                'e' => new BigInteger(JWT::urlsafeB64Decode($jwk['e']), 256),
                'n' => new BigInteger(JWT::urlsafeB64Decode($jwk['n']),  256)
            ]
        );
        $rsa->setPublicKey();

        return $rsa->getPublicKey();
    }
}
