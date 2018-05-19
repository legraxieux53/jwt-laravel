<?php

namespace App\Http\Controllers;

use App\Http\Models\Person;
use Lnl\JWT\AuthenticationManager;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class PersonController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $Persons = Person::all();
        return $Persons;
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $password = password_hash($request->password, PASSWORD_DEFAULT);
        $Person = new Person();
        $Person->nom = $request->nom;
        $Person->email = $request->email;
        $Person->code_pers = $request->code_pers;
        $Person->cel = $request->cel;
        $Person->tel = $request->tel;
        $Person->slogan = $request->slogan;
        $Person->password = $password;
        $Person->save();

        // authentification
        return $this->authenticate($request->code_pers, $request->password);
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        $Person = Person::findOrFail($id);
        return $Person;
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        $password = password_hash($request->password, PASSWORD_DEFAULT);
        $Person = Person::findOrFail($id);
        (!empty($request->nom))? $Person->nom = $request->nom : null;
        (!empty($request->email))? $Person->email = $request->email : null;
        (!empty($request->code_pers))? $Person->code_pers = $request->code_pers : null;
        (!empty($request->cel))? $Person->cel = $request->cel : null;
        (!empty($request->tel))? $Person->tel = $request->tel : null;
        (!empty($request->slogan))? $Person->slogan = $request->slogan : null;
        (!empty($request->password) && !empty($request->password_old) && password_verify($request->password_old, $Person->password))? $Person->password = $request->password : null;
        $Person->save();
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        $Person = Person::findOrFail($id);
        $Person->softDelete();
    }

    /**
     * Réalise l'oppération de connexion
     * @param  Request $request [description]
     * @return [type]           [description]
     */
    public function login (Request $request)
    {
        return $this->authenticate($request->code_pers, $request->password);
    }


    /**
     * Réalise l'oppération de déconnexion
     * @param  Request $request [description]
     * @return [type]           [description]
     */
    public function logout ($token)
    {
        $manager = new AuthenticationManager();
        $manager->setToken($token);
        $status = $manager->logout();
        if($status == AuthenticationManager::LOGOUT_SUCCESS) {
            return response()->json(["operation" => "success", "message" => "Déconnexion effectuée avec succès"], 200);
        }
        if($status == AuthenticationManager::LOGOUT_ERROR) {
            return response()->json(["operation" => "error", "message" => "Echec de l'oppération de déconnexion"], 403);
        }
    }

    /**
     * [authenticate description]
     * @return [type] [description]
     */
    private function authenticate ($username, $password)
    {
        $manager = new AuthenticationManager();
        $manager->setTable("Person");
        $manager->setUsernameField("code_pers");
        $manager->setPasswordField("password");
        //$obj = $this->table->where($this->username_field, $this->username)->first();
        $manager->setTablePath("App\\Http\\Models");
        $manager->setUsername($username);
        $manager->setPassword($password);
        $status = $manager->login();
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
}
