<?php

namespace App\Http\Middleware;

use Lnl\JWT\Token;
use Closure;

class AuthenticationPerson
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $token = new Token();
        $token->clean();
        $token->setToken($request->token);
        $token->setAgent("Person");
        if ($token->tokenVerifyAgent() && $token->isToken() && $token->isValid()) {
            $token->relance(3600);
            return $next($request);
        } else {
            return response()->json(["Error Message" => "Invalid token provided"], 403);
        }
    }
}
