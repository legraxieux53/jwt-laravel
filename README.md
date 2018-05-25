# jwt-laravel
Implementation of custom middleware that manage tokens for authentication in laravel framework. 

## Install
`composer require legracieux53/jwt-laravel` or `composer require legracieux53/jwt-laravel:dev-master`

## Usage

In your controller, import `AuthenticationManager` class and create authenticate function like that follow.

```php
	...
	use Lnl\JWT\AuthenticationManager;

	...


	private function authenticate ($username, $password)
    {
        $manager = new AuthenticationManager();
        $manager->setTablePath("App\\Http\\Models"); // Set model namespace
        $manager->setTable("Person"); // set model table name
        $manager->setUsernameField("code_pers"); // set username field in table
        $manager->setPasswordField("password"); // set password field in table
        $manager->setUsername($username); //set username value
        $manager->setPassword($password); // set password value
        $status = $manager->login(); // perform login and get his state for checking
        if ($status == AuthenticationManager::LOGIN_SUCCESS) {
            return response()->json(["token" => $manager->getToken()], 200);
        } else {
            if ($status == AuthenticationManager::ERROR_USERNAME) {
                return response()->json(["message error" => "Vérifiez votre username ou mot de passe"], 403);
            }
            if ($status == AuthenticationManager::ERROR_PASSWORD) {
                return response()->json(["message error" => "Vérifiez votre mot de passe"], 403);
            }
        }
    }
```

Then use your `authenticate` function for login.

```php
	...

	public function login (Request $request)
    {
        return $this->authenticate($request->code_pers, $request->password);
    }

	public function logout ($token)
    {
        $manager = new AuthenticationManager();
        $manager->setToken($token); // set token must be disabled
        $status = $manager->logout();
        if($status == AuthenticationManager::LOGOUT_SUCCESS) {
            return response()->json(["operation" => "success", "message" => "Déconnexion effectuée avec succès"], 200);
        }
        if($status == AuthenticationManager::LOGOUT_ERROR) {
            return response()->json(["operation" => "error", "message" => "Echec de l'oppération de déconnexion"], 403);
        }
    }
  	...

```

Now Create a middleware for checking authentication.

```php

namespace App\Http\Middleware;

use Lnl\JWT\Token; //import The token class
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
        $token->clean(); // remove all expired tokens
        $token->setToken($request->token); // set token that your request has send.
        $token->setAgent("Person"); // set agent of token. It used for group tokens in authentication level. Use table name by default if AuthenticationManager::setAgent($agent) has not called in authentication function
        if ($token->tokenVerifyAgent() && $token->isToken() && $token->isValid()) {
            $token->relance(3600); // define new time for token
            return $next($request);
        } else {
            return response()->json(["Error Message" => "Invalid token provided"], 403);
        }
    }
}

```


You can now call `login` and `logout` functions in your routes like this:

```php
Route::post('login/person', 'PersonController@login');


/**
 * Test de validité du token
 */
Route::middleware(['auth.ecole'])->group(function () {
    Route::get('logout/person/{token}', 'PersonController@logout');
    Route::get('test', function () {
        return response()->json(["message" => "connexion RAS"], 200);
    });
});

``` 