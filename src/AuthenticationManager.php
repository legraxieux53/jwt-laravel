<?php

namespace Lnl\JWT;

/**
* 
*/
class AuthenticationManager
{
	////////////////
	// constantes //
	////////////////
	const ERROR_PASSWORD = 5031;
	const ERROR_USERNAME = 504;
	const LOGIN_SUCCESS = 201;
	const LOGOUT_SUCCESS = 203;
	const LOGOUT_ERROR = 534;

	///////////////
	// variables //
	// ////////////
    private $token;
    private $username;
    private $password;
    private $username_field;
    private $password_field;
    private $table;
    private $table_path;

    /**
     * AuthenticationManager constructor.
     */
	public function __construct()
	{
		# code...
	}

	/**
	 * Réalise l'oppération de connexion
	 * @return [type] [description]
	 */
	public function login ()
	{
	    $cla = $this->table_path . '\\' . $this->table;
		$obj = $cla::where($this->username_field, $this->username)->first();
        if (!empty($obj)){
            $password_hash = $obj->getAttribute($this->password_field);
            if (password_verify($this->password, $password_hash)) {
                $token = new Token();
                $token->init("", $this->table, 3600, $this->username, $this->password);
                $token->setToken($token->generate());
                $token->create();
                $this->token = $token->getToken();
                return self::LOGIN_SUCCESS;
            } else {
                return self::ERROR_PASSWORD;
            }
        } else {
            return self::ERROR_USERNAME;
        }
	}

	/**
	 * Réalise l'oppération de déconnexion
	 * @return [type] [description]
	 */
	public function logout ()
	{
	    try {
            $token = new Token();
            $token->init($this->token, $this->table, null, $this->username, $this->password);
            $token->delete();
            return self::LOGOUT_SUCCESS;
        } catch (\Exception $e) {
            return self::LOGOUT_ERROR;
        }
	}

	/**
	 * Défini le nom utilisateur
	 * @param [type] $username [description]
	 */
	public function setUsername ($username)
	{
		$this->username = $username;
	}

	/**
	 * Défini le namespace de la table
	 * @param [type] $path [description]
	 */
	public function setTablePath ($path)
	{
		$this->table_path = $path;
	}

	/**
	 * Défini le mot de passe
	 * @param [type] $password [description]
	 */
	public function setPassword ($password)
	{
		$this->password = $password;
	}

	/**
	 * Défini le nom du champ correspondant au username dans la table
	 * @param [type] $field [description]
	 */
	public function setUsernameField ($field)
	{
		$this->username_field = $field;
	}

	/**
	 * Défini le nom du champ correspondant au password dans la table
	 * @param [type] $field [description]
	 */
	public function setPasswordField ($field)
	{
		$this->password_field = $field;
	}

	/**
	 * Défini le nom de la table
	 * @param [type] $table [description]
	 */
	public function setTable ($table)
	{
		$this->table = $table;
	}

	/**
	 * Défini un token récupéré pour certaines oppérations
	 * @param [type] $token [description]
	 */
	public function setToken ($token)
	{
		$this->token = $token;
	}

	/**
	 * Récupère le token
	 * @return [type] [description]
	 */
	public function getToken ()
    {
        return $this->token;
    }
}