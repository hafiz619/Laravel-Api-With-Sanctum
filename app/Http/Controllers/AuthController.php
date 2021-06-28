<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    public function register(Request $request){
        $field=$request->validate([
            'name'=>'required|string',
            'email'=>'required|string|unique:users,email',
            'password'=>'required|string',
        ]);
        $user=User::create([
          'name'=>$field['name'],
          'email'=>$field['email'],
          'password'=>bcrypt($field['password']),
        ]);
        $token = $user->createToken('hafiz-t')->plainTextToken;

        $response=[
            'user'=>$user,
            'token'=>$token
        ];
        return response($response,201);
    }

    public function login(Request $request){
        $field=$request->validate([

            'email'=>'required|string',
            'password'=>'required|string',
        ]);
    //    email
    $user=User::where('email',$field['email'])->first();
    // passsword
    if (!$user || !Hash::check($field['password'], $user->password)) {
        return response([
            'message'=>'hello you are login now'
        ],401);
    }

        $token = $user->createToken('hafiz-t')->plainTextToken;

        $response=[
            'user'=>$user,
            'token'=>$token
        ];
        return response($response,201);
    }

    public function logout(Request $request){
        Auth()->user()->tokens()->delete();
        return [
            'message'=>'logout'
        ];
    }
}
