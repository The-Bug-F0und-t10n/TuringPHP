<?php

namespace zion\core;

use DateTime;
use Exception;
use zion\utils\DateTimeUtils;
use zion\utils\FileUtils;

/**
 * @author Vinicius
 * @since 08/05/21
 * 
 * Como usar
 * Chamar o método createSession() apenas para criar o cookie de sessão ao efetuar o login por exemplo.
 * Após o cookie estiver criado no frontend, basta chamar os métodos set e get. A sessão vai expirar no 
 * tempo configurado na classe e o arquivo no servidor será deletado. O cookie no frontend nunca é eliminado
 * pela classe (Cookie de Sessao)
 */
class Session
{
    public static $sessionKey = "SESSIONID";

    /**
     * Tempo para expirar a sessão em segundos
     * 3600 segundos = 1 hora
     * 86400 segundos = 1 dia
     *14400 =  4 horas 
     * @var integer
     */

    private static $expireTime  = 14400;
    private static $id          = null ;
    private static $initialized = false;
    private static $data        = array();
    private static $info        = array();
    private static $folder      = "/tmp/";

    /**
     * Retorna o id da sessão
     * @return string
     */
    public static function getId()
    {
        return self::$id;
    }
    /**
     * Valida a sessão 
     */
    public static function validSession():bool{
        if(!self::hasValidCookie()){
            return false;
        }

        return is_null(self::load())? true: false; 
    } 
    /**
     * Retorna todas as variáveis de sessão
     * @return array
     */
    public static function getAll()
    {
        self::init();
        return self::$data;
    }

    /**
     * Adiciona uma variável dentro de um array de sessão
     * @param string $key
     * @param mixed $value
     */
    public static function add(string $key,mixed $value)
    {
        self::init();
        if (!array_key_exists($key, self::$data)) {
            self::$data[$key] = array();
        }
        self::$data[$key][] = $value;
        self::write();
    }

    /**
     * Define uma variável na sessão
     * @param string $key
     * @param mixed $value
     */
    public static function set(string $key, mixed $value):void
    {
        self::init();
        self::$data[$key] = $value;
        self::write();
    }

    /** 
     * Verifica se existe uma sessão com dados atribuidos
     * 
     * **/
    public static function hasData()
    {
        self::init();
        return (sizeof(self::$data) > 0);
    }

    /**
     * Verifica a existência da sessão e valida sua chave 
     */
    public static function hasValidCookie()
    {
        return array_key_exists(self::$sessionKey, $_COOKIE) and $_COOKIE[self::$sessionKey] != "";
    } 

    /**
     * Retorna uma variável de sessão
     * @param string $key
     * @return mixed
     */
    public static function get(string $key):mixed
    {
        self::init();
        return array_key_exists($key,self::$data)? self::$data[$key]:null;    
    }
    
    /**
     *  Verifica a exixtência de uma sessão ativa e a carrega
     */
    private static function init():void
    {
        if (self::$initialized) {
            return;
        }
        self::$folder = \zion\APP_ROOT . "tmp" . \DS . "session" . \DS;
    
        if (empty(self::$id) && !empty($_COOKIE)) {
    
            self::$id = $_COOKIE[self::$sessionKey];
        }
        
        if (self::hasValidCookie()){
            self::load();
        }

        self::$initialized = true;
    }

    /**
     * Retorna o caminho do arquivo de sessão
     * @param string $id
     * @return string
     */
    private static function getFile($id = null)
    {
        if ($id !== null) {
            return self::$folder . $id . ".session";
        }
        return self::$folder . self::$id . ".session";
    }

    /**
     * Cria uma sessão 
     */
    public static function createSession(string $id = null):void
    {
        // se o cookie de sessão já esta no navegador, reutiliza o id
        if (!empty(isset($_COOKIE[self::$sessionKey]))) {
            self::$id = $_COOKIE[self::$sessionKey];

            if (sizeof(self::$info) <= 0) {
                self::$info = self::createInfo();
            }

            return;
        }

        // gerando id de sessão
        if (is_null($id)) {
            $id = hash("sha256", uniqid("server1", true) . random_int(100000, 999999));
        }

        // enviando instrução para criar o cookie no cabeçalho da resposta
        // lembrando que cookies de sessão são eliminados ao sair do navegador
        //$domain = ".".$_SERVER["SERVER_NAME"];
        $domain = "";
        setcookie(self::$sessionKey, $id, 0, "/", $domain, false, false);

        // definindo id e inicializando sessão
        self::$id   = $id;
        self::$info = self::createInfo();
    }

    /**
     * Gera metadados da sessão
     * @return array
     */
    private static function createInfo()
    {
        $created = new DateTime();
        $expire  = new DateTime();
        $expire->modify("+" . self::$expireTime . " seconds");

        return array(
            "ipv4"      => $_SERVER["REMOTE_ADDR"],
            "userAgent" => $_SERVER["HTTP_USER_AGENT"],
            "expireTime" => self::$expireTime,
            "created"   => $created,
            "expire"    => $expire
        );
    }

    /**
     * Retorna os metadados da sessão atual
     * @return array
     */
    public static function getInfo()
    {
        return self::$info;
    }

    /**
     * Carrega a sessão do arquivo para a memória
     */
    private static function load()
    {

        if (!self::hasValidCookie()) {
            return;
        }
        
        $file = self::getFile();

        if (file_exists($file)) {
   
            $content = unserialize(file_get_contents($file));
                
            if (is_array($content)) {
                self::$data = $content["data"];
                self::$info = $content["info"];
                $content = null;
            } else {
                // o arquivo existe mas seu conteúdo é inválido, deletando-o
                if (FileUtils::canDelete($file)) {
                    unlink($file);
                }
            }
            $content = null;
        } else {
            self::$info = self::createInfo();
        }
        
        // Verifica a expiração da sessão e deleta os dados
        if (self::$info["expire"] < new DateTime()) {
            self::$data = array();

            if (FileUtils::canDelete($file)) {
                unlink($file);
                return false;
            }
        }
    }

    /**
     * Grava a sessão da memória para o disco
     * @throws Exception
     */
    private static function write()
    {
        $content = array(
            "data" => self::$data,
            "info" => self::$info
        );

        if (sizeof($content["data"]) <= 0) {
            return;
        }

        if (sizeof($content["info"]) <= 0) {
            throw new Exception("Erro ao gravar sessão, há data mas não info");
        }

        $file = self::getFile();
				$f = fopen($file, "w");

        if ($f !== false) { 
            fwrite($f, serialize($content));
            fclose($f);
				}

    }

    /**
     * Destrói a sessão
     * @param string $id
     */
    public static function destroy($id = null)
    {
        self::init();

        // Apagando dados do disco
        $file = self::getFile($id);
        if (file_exists($file) and FileUtils::canDelete($file)) {
            @unlink($file);

            return false;
        }

        if ($id === null) {
            // Apagando dados em memória 
            self::$data = array();
        }
 
        self::cleanFilesSession();

        //Apagando cookie 
        setcookie('SESSIONID', '', 0, "/", '', false, false);
    }

    /**
     * Limpa os arquivos de sessão
     */
    public static function cleanFilesSession()
    {
        $folder = self::$folder;
        $files = scandir($folder);
        foreach ($files as $filename) {
            if ($filename == "." || $filename == "..") {
                continue;
            }

            if (strpos($filename, ".session") === false) {
                continue;
            }

            $file = $folder . $filename;

            $dateFile = new DateTime(date("Y-m-d H:i:s", filemtime($file)));
            $secs = DateTimeUtils::getSecondsDiff(new DateTime(), $dateFile);

            match(true){
                ($secs >= self::$expireTime) => unlink($file),
                default => null
            };
        }
    }
}
