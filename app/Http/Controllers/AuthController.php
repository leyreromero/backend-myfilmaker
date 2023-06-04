<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use PhpParser\Node\Stmt\TryCatch;

class AuthControler extends Controller
{
    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => 'required|string|min:2|max:25',
                'email' => 'required|string|unique:users,email',
                'password' => 'required|string|min:6|max:12',
            ]);

            $user = User::create([
                'name' => $request->input('name'),
                'email' => $request['email'],
                'password' => bcrypt($request['password'])
            ]);

            $token = $user->createToken('apiToken')->plainTextToken;

            return response()->json(
                [
                    "success" => true,
                    "message" => "User registered successfully",
                    'data' => $user,
                    "token" => $token
                ],
                201
            );
        } catch (\Throwable $th) {
            return response()->json(
                [
                    "success" => false,
                    "message" => "Cant register user",
                    "data" => $th->getMessage()
                ],
                500
            );
        }
    }

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => 'required|string',
                'password' => 'required|string',
            ]);

            $email = $request['email'];

            $user = User::query()->where('email', $email)->first();

            // Validamos si el usuario existe
            if (!$user) {
                return response()->json(
                    [
                        "success" => true,
                        "message" => "Email or password are invalid"
                    ],
                    404
                );
            }

            // Validamos la contraseña
            if (!Hash::check($request['password'], $user->password)) {
                return response()->json(
                    [
                        "success" => true,
                        "message" => "Email or password are invalid"
                    ],
                    404
                );
            }

            $token = $user->createToken('apiToken')->plainTextToken;

            return response()->json(
                [
                    "success" => true,
                    "message" => "User logged successfully",
                    "token" => $token
                ],
                200
            );
        } catch (\Throwable $th) {
            return response()->json(
                [
                    "success" => false,
                    "message" => "Cant login user",
                    "data" => $th->getMessage()
                ],
                500
            );
        }
    }

    public function profile()
    {
        try {
            $user = auth()->user();

            return response(
                [
                    "success" => true,
                    "message" => "User profile get succsessfully",
                    "data" => $user
                ],
                200
            );
        } catch (\Throwable $th) {
            return response()->json(
                [
                    "success" => false,
                    "message" => "Profile cant be retrieved",
                    "data" => $th->getMessage()
                ],
                500
            );
        }
    }
}
