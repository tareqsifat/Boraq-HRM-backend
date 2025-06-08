<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Services\AuthService;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(LoginRequest $request)
    {
        $authService = new AuthService();
        $login = $authService->login($request);

        if($login['success'] === false) {
            return response()->json([
                'success' => false,
                'status' => $login['status'],
                'message' => $login['message'],
            ], $login['status']);
        }
        return response()->json([
            'success' => true,
            'status' => 200,
            'message' => $login['message'],
            'user' => $login['user'],
            'token' => $login['token'],
        ]);
    }
    public function register(RegisterRequest $request)
    {

        $authService = new AuthService();
        $user = $authService->register($request);
        if ($user['success'] === false) {
            return response()->json([
                'success' => false,
                'status' => $user['status'],
                'message' => $user['message'],
            ], $user['status']);
        }
        return response()->json([
            'success' => true,
            'status' => $user['status'],
            'message' =>  $user['message'],
        ]);
    }
    public function verifyEmail($token)
    {
        $user = User::where('email_verification_token', $token)->first();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid or expired verification token.',
            ], 404);
        }

        if ($user->hasVerifiedEmail()) {
            return response()->json([
                'success' => false,
                'message' => 'Email already verified.',
            ], 400);
        }

        $user->email_verified_at = now();
        $user->email_verification_token = null;
        $user->save();

        return response()->json([
            'success' => true,
            'message' => 'Email verified successfully.',
        ]);
    }
}
