<?php 
namespace Wpint\JWT;

use WPINT\Framework\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Wpint\JWT\Concrete\JWT;

class JWTServiceProvider extends ServiceProvider
{
   
    /**
     * Register JWT service.
     *
     * @return void
     */
    public function register() : void 
    {
        $this->app->bind('JWT', function(Application $app){
           return new JWT();
        });
    }

}