<?php
namespace zion\core;

use zion\utils\FileUtils;
use zion\utils\HTTPUtils;

/**
 * @author Vinicius Cesar Dias
 */
class App {
    /**
    * Mapea as rotas padrões para os módulos
    */
    public static function route(){

      $uri = explode("/",$_SERVER["REQUEST_URI"]);
        
				// URI no padrão rest
				if (!str_contains($_SERVER["REQUEST_URI"],"/{$_ENV['typeApi']}/{$_ENV['version']}")) {

					if (sizeof($uri) < 5) {
						HTTPUtils::status(400);
						HTTPUtils::sendHeadersNoCache();
						echo "Padrão de URI inválido (" . sizeof($uri) . ")";
						exit();
					}

					if (!in_array($_SERVER["REQUEST_METHOD"], array("GET", "POST", "PUT", "DELETE", "FILTER"))) {
						HTTPUtils::status(400);
						HTTPUtils::sendHeadersNoCache();
						echo "Método Rest inválido";
						exit();
					}

					// controle
					$module     = preg_replace("[^a-z0-9\_]", "", strtolower($uri[3]));
					$controller = preg_replace("[^a-zA-Z0-9]", "", $uri[4]);

					$className   = $controller . "Controller";
					$classNameNS = "\\app\\mod\\" . $module . "\\controller\\" . $controller . "Controller";
					$classFile   = \zion\APP_ROOT . "public/modules/" . $module . "/controller/" . $className . ".php";

					if (file_exists($classFile)) {
						require_once($classFile);
						$ctrl = new $classNameNS();

						$methodName = 'action'.$uri[5];
						if (method_exists($ctrl, $methodName)) {
							$ctrl->$methodName();
							die();
						}	
						echo "Falta o método";
					}
					die();
				}
			}
}
?>
