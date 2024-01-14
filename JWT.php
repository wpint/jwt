<?php 
namespace Wpint\JWT\Concrete;

use Carbon\Carbon;
use Firebase\JWT\JWT as JWTJWT;
use Firebase\JWT\Key;
use stdClass;

class JWT extends JWTJWT
{

    /**
     * Undocumented function
     *
     * @param string $secretKey
     * @param string $serverName
     * @param string $expireAt
     * @param string $algo
     * @param array $headers
     */
    public function __construct(
        private $secretKey = '', 
        private $serverName = '',
        private $expireAt = '6', // minutes
        private $algo = 'HS512',
        private $headers = [],
    )
    {
        $this->secretKey = env('APP_KEY');
        $this->serverName = env('APP_URL');
    }

    /**
     * set Expiration time for jwt 
     *
     * @param string $expireAt
     * @return self
     */
    public function setExpireAt(string $expireAt) : self
    {
        $this->expireAt = $expireAt;
        return $this;
    }

    /**
     * Set algo for jwt
     *
     * @param string $algo
     * @return self
     */
    public function setAlgo(string $algo) : self
    {
        $this->algo = $algo;
        return $this;
    }

    /**
     * Generate new encoded data with jwt
     *
     * @param array $payload
     * @param array $headers
     * @return void
     */
    public function generate($payload = [], $headers = []) 
    {
        
        $issuedAt = Carbon::now();
        $data = [
            'iat'  => $issuedAt->timestamp,         // Issued at: time when the token was generated
            'iss'  => $this->serverName,            // Issuer
            'nbf'  => $issuedAt->timestamp,         // Not before
            'exp'  => $issuedAt->addMinutes($this->expireAt),                           // Expire
        ];

        return self::encode( 
            array_merge($data, $payload),
            $this->secretKey, 
            $this->algo,
            null,
            $headers
        );
        
    }

    /**
     * decode the given jwt with Key class
     *
     * @param [type] $jwt
     * @return void
     */
    public function data($jwt)
    {   
        return self::decode($jwt, new Key($this->secretKey, $this->algo), $headers);
    }

    /**
     * Validate the token
     *
     * @param string $token
     * @return boolean
     */
    public function validate(string $token): bool
    {
        $token = self::decode($token, new Key($this->secretKey, $this->algo), $headers = new stdClass());
        $now = Carbon::now();
        if($token->iss !== $this->serverName ||
        $token->nbf > $now->timestamp || 
        $token->exp < $now->timestamp
        ){
            return false;
        }

        return true;
    }

}