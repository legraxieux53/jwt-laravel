<?php

namespace Lnl\JWT;

use Lnl\IO\Files\File as MyFile;

/**
* 
*/
class Token
{	
	////////////////
	// constantes //
	////////////////
	const TOKEN_FILE_SAVING = "public/modules/auths/token.lnt";
	const DEFAULT_AGENT = "all_person";
	const DEFAULT_USERNAME = "username";
	const DEFAULT_PASSWORD = "password";
	const ERROR = 500;

	///////////////
	// variables //
	///////////////
	private $token;
	private $agent;
	private $username;
	private $password;
	private $duree = 3600;
	private $validite;



    /**
     * Token constructor.
     */
	public function __construct()
    {
        $file = new MyFile();
        $file->init(self::TOKEN_FILE_SAVING);
	    $file->create();
    }

    /**
	 * intitie un nouveau token
	 * @param  string  $token [description]
	 * @param  integer $duree [description]
	 * @return [type]         [description]
	 */
	public function init ($token = "", $agent = self::DEFAULT_AGENT, $duree = 3600, $username = self::DEFAULT_USERNAME, $password = self::DEFAULT_PASSWORD)
	{
		$this->token = $token;
		$this->duree = $duree;
		$this->agent = $agent;
		$this->username = $username;
		$this->password = $password;
	}

	/**
	 * crée le token
	 * @return [type] [description]
	 */
	public function create ()
	{
		if (!$this->isToken()) {
			$this->validite = time() + $this->duree;
			$file = new MyFile;
			$file->init(self::TOKEN_FILE_SAVING);
			$file->write($this->mouleTokenFile($this->token, $this->validite));
		} else {
		    $this->$this->relance($this->duree);
        }
	}

	/**
	 * supprime le token
	 * @return [type] [description]
	 */
	public function delete ()
	{
		if ($this->isToken()) {
		    $this->deleteOffset($this->tokenOffset());
        }
	}

	/**
	 * supprime le token
	 * @return [type] [description]
	 */
	private function deleteOffset ($offset)
	{
	    if (count($this->tokenFileToTableLine()) > $offset) {
            $line = $this->tokenFileToTableLine()[$offset];
            $line .= "\n";
            $file = new MyFile();
            $file->init(self::TOKEN_FILE_SAVING);
            $file->deleteLine($line);
        }
	}

	/**
	 * vérifie si une chaine de caractères est un token
	 * @return boolean      [description]
	 */
	public function isToken ()
	{
	    $found = false;
	    $cpt = 0;
	    while ($cpt < count($this->tokenFileToTable()) && !$found) {
			if ($this->tokenFileToTable()[$cpt]["token"] == $this->token) {
			    $found = true;
            } else {
			    $cpt++;
            }
		}

		return $found;
	}

	/**
	 * génère un token
	 * @return [type] [description]
	 */
	public function generate ()
	{
		return password_hash($this->agent, PASSWORD_DEFAULT) . password_hash($this->username . $this->password, PASSWORD_DEFAULT);
	}

	/**
	 * défini le username
	 * @param [type] $username [description]
	 */
	public function setUsername ($username)
	{
		$this->username = $username;
	}

	/**
	 * défini le password
	 * @param [type] $password [description]
	 */
	public function setPassword ($password)
	{
		$this->password = $password;
	}

	/**
	 * Défini le token
	 * @param [type] $token [description]
	 */
	public function setToken ($token)
	{
		$this->token = $token;
	}

	/**
	 * définir la durée du token
	 * @param [type] $duree [description]
	 */
	public function setDuree ($duree)
	{
		$this->duree = $duree;
	}

	/**
	 * défini l'agent du token
	 * @param [type] $agent [description]
	 */
	public function setAgent ($agent)
	{
		$this->agent = $agent;
	}

	/**
	 * retourne le username
	 * @return string [description]
	 */
	public function getUsername () 
	{
		return $this->username;
	}

	/**
	 * retourne le password
	 * @return string [description]
	 */
	public function getPassword ()
	{
		return $this->password;
	}

	/**
	 * retourne le token
	 * @return string [description]
	 */
	public function getToken ()
	{
		return $this->token;
	}

	/**
	 * retourne la duréee du token
	 * @return [type] [description]
	 */
	public function getDuree ()
	{
		return $this->duree;
	}

	/**
	 * retourne l'agent 
	 * @return string [description]
	 */
	public function getAgent ()
	{
		return $this->agent;
	}

	/**
	 * Vérifie que l'agent du token est correct
	 * @return [type]        [description]
	 */
	public function tokenVerifyAgent ()
    {
        if (strlen($this->token) >= 120) {
            $agentToken = substr($this->token, 0, 60);
            return password_verify($this->agent, $agentToken);
    	} else {
    		return false;
    	}
    }

    /**
     * vérifie que le username et le mot de passe sont correctes
     * @return [type] [description]
     */
	public function tokenVerifyIds ()
    {
    	if (strlen($this->token) >= 120) {
	        $idsToken = substr($this->token, 60, 60);
	        $ids = $this->username . $this->password;
	        return password_verify($ids, $idsToken);
    	} else {
    		return false;
    	}
    }

    /**
     * vérifie que le token corespond aux identifiants
     * @return [type] [description]
     */
    public function tokenVerify ()
    {
        if ($this->agent == "*") {
            return $this->tokenVerifyIds();
        } else {
            return $this->tokenVerifyAgent() && $this->tokenVerifyIds();
        }
    }

	/**
	 * genere le code du token
	 * @return [type] [description]
	 */
	private function generateCode () 
	{
	    $chars = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9'];
	    $cod = self::DEFAULT_AGENT;
	    for ($i=0; $i < 9; $i++) { 
	        $cod .= $chars[mt_rand(0, count($chars) - 1)];
	    }
	    $cod .= time();
	    return $cod;
	}

	/**
	 * retourn l'offset du token
	 * @return [type] [description]
	 */
	private function tokenOffset ()
	{
		$found = false;
	    $cpt = 0;
	    while ($cpt < count($this->tokenFileToTable()) && !$found) {
			if ($this->tokenFileToTable()[$cpt]["token"] == $this->token) {
			    $found = true;
            } else {
			    $cpt++;
            }
		}

		if ($found) {
			return $cpt;
		} else {
			return -1;
		}
	}

	/**
	 * Vérifie la validité d'un token
	 * @return boolean [description]
	 */
	public function isValid ()
	{
        if ($this->isToken()) {
            return $this->isValidOffset($this->tokenOffset());
        } else {
            return false;
        }
	}

	/**
	 * Relance la durée du token
	 * @param  integer $duree [description]
	 * @return [type]         [description]
	 */
	public function relance ($duree)
	{
        if ($this->isToken()) {
            $validite = $this->tokenFileToTable()[$this->tokenOffset()]["validite"];
            $search = "/validite/" . $validite;
            $replace = "/validite/" . (intval($duree) + time());
            $file = new MyFile();
            $file->init(self::TOKEN_FILE_SAVING);
            $contents = $file->read();
            $new_content = str_replace($search, $replace, $contents);
            $file->writeOver($new_content);
        }

	}

	/**
	 * Supprime les tokens invalides
	 * @return [type] [description]
	 */
	public function clean ()
	{
	    while ($this->hasInvalidToken()) {
            $this->deleteOffset($this->getFirstInvalidOffset());
        }
	}

	/**
	 * Retourne un tableau multidimentionnel contenant la liste des tokens
	 * @return [type] [description]
	 */
	private function tokenFileToTable()
	{
	    try {
            $lines = $this->tokenFileToTableLine();
            // recuperer les champs
            $linesTab = array();
            for ($i=0; $i < count($lines); $i++)
            {
                if (count($lines) > 1){
                    $tabA = explode("/token/", $lines[$i]);
                    if(count($tabA) > 1) {
	                    $tabB = explode("/validite/", $tabA[1]);
	                    if(count($tabB) > 1) {
		                    $ltab = array("token" => $tabB[0], "validite" => $tabB[1]);
		                    $linesTab[] = $ltab;	                    	
	                    }
                    }
                }
            }

            return $linesTab;
        } catch (\Exception $e) {
	        return self::ERROR;
        }
	}


	/**
	 * Retourne un tableau contenant la liste des tokens
	 * @return [type] [description]
	 */
	private function tokenFileToTableLine()
	{
		$file = new MyFile;
		$file->init(self::TOKEN_FILE_SAVING);
		$content = $file->read();
        $lines = explode("\n", $content);

        return $lines;
	}

	/**
	 * vérifie s'il existe un token invalide dans la liste
	 * @return boolean [description]
	 */
	private function hasInvalidToken()
	{
		if($this->getFirstInvalidOffset() != -1)
        {
            return true;
        } else {
		    return false;
        }
	}


	/**
	 * retourne le premier offset du token invalide
	 * @return [type] [description]
	 */
	private function getFirstInvalidOffset()
	{
        $found = false;
        $cpt = 0;
        while ($cpt < count($this->tokenFileToTableLine()) && !$found)
        {
            if (!$this->isValidOffset($cpt)) {
                if (strlen($this->tokenFileToTableLine()[$cpt]) >= 120) {
                    $found = true;
                } else {
                    $cpt = $cpt + 1;
                }
            } else {
                $cpt = $cpt + 1;
            }
        }
        
        if ($found) {
        	return $cpt;
        } else {
        	return -1;
        }
	}

	/**
	 * détermine l'état de validité d'un token
	 * @param  int  $offset [description]
	 * @return boolean         [description]
	 */
	private function isValidOffset ($offset)
	{
        if (isset($this->tokenFileToTable()[$offset])){
            if (intval($this->tokenFileToTable()[$offset]["validite"]) >= time()) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

	/**
	 * defini le moule (formatage) du token dans le fichier
	 * @param  string $token    [description]
	 * @param  string $validite [description]
	 * @return [type]           [description]
	 */
	private function mouleTokenFile($token, $validite)
	{
		return "/token/" . $token . "/validite/" . $validite ."\n";
	}




}