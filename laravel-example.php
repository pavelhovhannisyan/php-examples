<?php

namespace App\Http\Controllers;

use App\PasswordReset;
use App\Role;
use App\User;
use Hash;
use Illuminate\Foundation\Auth\ResetsPasswords;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use JWTAuth;
use Response;
use Validator;
use App\Mail\ResetPasswordEmail;
use Illuminate\Support\Facades\Mail;

class APIAuthController extends Controller
{
    use ResetsPasswords;

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:50|unique:user',
            'first_name' => 'required|max:50',
            'last_name' => 'required|max:50',
            'password' => 'required|max:100'
        ]);

        if ($validator->fails()) {
            $this->template->pushError($validator->errors());
            return response()->json($this->template->getResponse(), 400);
        }

        $user = User::create([
            'first_name' => $request->get('first_name'),
            'last_name' => $request->get('last_name'),
            'email' => $request->get('email'),
            'password' => bcrypt($request->get('password')),
        ]);

        $role_user = Role::where('name', 'user')->first();
        $user->roles()->attach($role_user);

        $token = JWTAuth::fromUser($user);
        $user = $user->with('roles')->find($user->id);

        $this->template->addPayloadItem(compact(['token', 'user']));
        return response()->json($this->template->getResponse());
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:50',
            'password' => 'required'
        ]);

        if ($validator->fails()) {
            $this->template->pushError($validator->errors());
            return response()->json($this->template->getResponse(), 400);
        }

        $credentials = $request->only('email', 'password');

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                $this->template->pushError(['invalid_credentials' => 'Wrong username or password']);
                return response()->json($this->template->getResponse(), 401);
            }
        } catch (JWTException $e) {
            $this->template->pushError(['server_error' => 'Could not create token']);
            return response()->json($this->template->getResponse(), 500);
        }

        $userId = Auth::user()->id;
        $user = User::with('roles')->find($userId);

        $this->template->addPayloadItem(compact(['token', 'user']));
        return response()->json($this->template->getResponse(), 200);
    }

    public function logout(Request $request)
    {
        JWTAuth::invalidate(JWTAuth::getToken());
        $this->template->addPayloadItem(['success' => 'logging_out']);
        return response()->json($this->template->getResponse(), 200);
    }

    public function getToken(Request $request)
    {
        $token = (string)JWTAuth::getToken()->get();
        $this->template->addPayloadItem(compact(['token']));
        return response()->json($this->template->getResponse(), 200);
    }

    public function refreshToken(Request $request)
    {
        $token = JWTAuth::getToken();
        $newToken = JWTAuth::refresh($token);
        $this->template->addPayloadItem(compact(['newToken']));
        return response()->json($this->template->getResponse(), 200);
    }

    public function sendResetPasswordMail(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:50'
        ]);
        if ($validator->fails()) {
            $this->template->pushError($validator->errors());
            return response()->json($this->template->getResponse(), 400);
        }
        $user = User::where('email', $request->input('email'))->first();
        if (!$user) {
            $this->template->pushError(['user_not_found' => 'User not found.']);
            return response()->json($this->template->getResponse(), 400);
        }
        $token = $this->broker()->createToken($user);
        Mail::to($user)->send(new ResetPasswordEmail($user->toArray(), env('FRONT_URL') . "/auth/reset_password/$user->email/$token"));
        $this->template->addPayloadItem(['success' => 'Mail send successfully.']);
        return response()->json($this->template->getResponse(), 200);
    }

    public function reset(Request $request, $email, $token)
    {
        $validator = Validator::make([$email], ['required|string|email|max:50']);
        if ($validator->fails()) {
            $this->template->pushError($validator->errors());
            return response()->json($this->template->getResponse(), 400);
        }
        $reset = PasswordReset::where('email', $email)->first();
        if (Hash::check($token, $reset->token)) {
            if( $request->isMethod('post')) {
                $validator = Validator::make($request->all(), [
                    'password' => 'required|confirmed|string|min:6',
                    'password_confirmation' => 'required|string|min:6'
                ]);
                if ($validator->fails()) {
                    $this->template->pushError($validator->errors());
                    return response()->json($this->template->getResponse(), 400);
                }
                $user = User::where('email', $email)->with('roles')->first();
                $user->password = bcrypt($request->get('password'));
                $user->save();
                $token = \JWTAuth::fromUser($user);
                $this->template->addPayloadItem(compact(['token', 'user']));
                return response()->json($this->template->getResponse(), 200);
            }else {
                $this->template->addPayloadItem(['success' => 'The token is valid.']);
                return response()->json($this->template->getResponse(), 200);
            }

        } else {
            $this->template->pushError(['invalid_token' => 'The token is not valid.']);
            return response()->json($this->template->getResponse(), 400);
        }
    }

    public function changePassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'password' => 'required|confirmed|string|min:6',
            'password_confirmation' => 'required|string|min:6'
        ]);
        if ($validator->fails()) {
            $this->template->pushError($validator->errors());
            return response()->json($this->template->getResponse(), 400);
        }
        $user = auth()->user();
        $user->password = bcrypt($request->get('password'));
        $user->save();
        $this->template->addPayloadItem(compact(['user']));

        return response()->json($this->template->getResponse(), 200);
    }
}
