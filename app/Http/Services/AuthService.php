<?php

namespace App\Http\Services;

use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Notification;
use App\Notifications\PasswordResetNotification;
use Illuminate\Support\Facades\DB;

class AuthService
{
    /**
     * Attempt to log in a user with the given credentials.
     *
     * @param array $credentials
     * @return User|null
     */
    public function login($request): ?array
    {
        $user = User::where('email', $request->email)->first();
        $remember = $request->has('remember') ? (bool)$request->remember : false;
        if (!$user || !Auth::attempt(['email' => $request->email, 'password' => $request->password], $remember)) {
            return [
                'success' => false,
                'status' => 401,
                'message' => 'Invalid credentials.',
            ];
        }
        $token = $user->createToken('Personal Access Token')->accessToken;
        return [
            'success' => true,
            'status' => 200,
            'message' => 'Logged in successfully.',
            'user' => $user,
            'token' => $token,
        ];
    }

    /**
     * Register a new user.
     *
     * @param array $data
     * @return User
     */
    public function register($request): array
    {
        $password = Hash::make($request->password);
        $token  = Str::uuid();
        $otp = rand(100000, 999999);
        $user = DB::transaction(function () use ($request, $password, $token, $otp) {
            // Create the user
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => $password,
            ]);


            // Create a verification token (polymorphic)
            $user->verificationTokens()->create([
                'token' => $token,
                'otp' => $otp,
                'verify_by' => 'email',
            ]);

            return $user; // Will be returned after commit
        });
        if (!$user) {
            return [
                'success' => false,
                'status' => 401,
                'message' => 'User registration failed.',
            ];
        }
        return [
            'success' => true,
            'status' => 201,
            'message' => 'User registered successfully.'
        ];
    }

    /**
     * Send a password reset link to the user's email.
     *
     * @param string $email
     * @return void
     */
    public function sendPasswordResetLink(string $email): void
    {
        Password::sendResetLink(['email' => $email]);
    }
    /**
     * Reset the user's password.
     *
     * @param string $token
     * @param string $password
     * @return User
     */
    public function resetPassword(string $token, string $password): User
    {
        $user = Password::getUser(['email' => Password::getEmailForToken($token)]);

        if (!$user || !Password::tokenExists($user, $token)) {
            throw ValidationException::withMessages(['email' => 'Invalid token or email.']);
        }

        $user->password = Hash::make($password);
        $user->save();

        return $user;
    }

    /**
     * Logout the currently authenticated user.
     *
     * @return void
     */
    public function logout(): void
    {
        Auth::logout();
    }
}
