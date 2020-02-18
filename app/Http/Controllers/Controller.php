<?php

namespace App\Http\Controllers;

use Laravel\Lumen\Routing\Controller as BaseController;
use Illuminate\Http\Request;

class Controller extends BaseController
{
    public function login(){
        $uuid = 'aaaaaaaa'; //Uuid::uuid4();
        $params = array(
            'client_id' => 'dev.clom.ao.auth',
            'redirect_uri' => 'https://ao.clom.dev/callback',
            'response_type' => 'code id_token',
            'response_mode' => 'form_post',
            'state' => $uuid
        );

        $appleUrl = 'https://appleid.apple.com/auth/authorize?'.http_build_query($params);

        return redirect($appleUrl);
        //return view('index');
    }

    public function callback(Request $req){
        $request = $req->getContent();

        return view('callback', ['data' => $request]);
    }
}
