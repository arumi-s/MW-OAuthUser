<?php

namespace MediaWiki\OAuthClient;

/**
 * MediaWiki OAuth User Info <=> Session Interface
 */
class User {
	/**
	 * variable names for storing tokens in session
	 * @var string
	 */
	const SESS_AK = 'access_key';
	const SESS_AS = 'access_secret';
	const SESS_RK = 'request_key';
	const SESS_RS = 'request_secret';

	/**
	 * Request Token before Authentication
	 * @var Token
	 */
	private $requestToken = null;

	/**
	 * Access Token after Authentication
	 * @var Token
	 */
	private $accessToken = null;

	/**
	 * Retrieved user basic information
	 * @var stdClass
	 */
	public $info = null;

	/**
	 * the MediaWiki OAuth client which is being used
	 * @var Client
	 */
	public $client = null;

	/**
	 * Last error
	 * @var Exception
	 */
	public $error = null;

	/**
	 * @param Client $client
	 * @param stdClass $info
	 */
	function __construct( Client &$client, $info = null ) {
		$this->client = $client;
		$this->info = $info;
	}

	/**
	 * Load user access token info from Session, or create new access token if needed and posible.
	 * Optional to retrieved user basic information.
	 *
	 * @param Client $client
	 * @param bool $check true if you want to retrieved user basic information
	 * and check is this token valid
	 * @return User
	 */
	static public function newFromSession ( Client &$client, $check = true ) {
		$newuser = new Self( $client );
		if ( session_status() != PHP_SESSION_ACTIVE ) return $newuser;
		if ( empty( $_SESSION[SELF::SESS_AK] ) || empty( $_SESSION[SELF::SESS_AS] ) ) {
			$verifyCode = empty( $_POST['oauth_verifier'] ) ? ( $_GET['oauth_verifier'] ?? '' ) : $_POST['oauth_verifier'];
			$verifyToken = empty( $_POST['oauth_token'] ) ? ( $_GET['oauth_token'] ?? '' ) : $_POST['oauth_token'];
			if ( !empty( $verifyCode ) && !empty( $verifyToken ) && 
				isset( $_SESSION[SELF::SESS_RK] ) && isset( $_SESSION[SELF::SESS_RS] ) && 
				$verifyToken === $_SESSION[SELF::SESS_RK]
			) {
				$newuser->requestToken = new Token( $_SESSION[SELF::SESS_RK], $_SESSION[SELF::SESS_RS] );
				try {
					$newuser->accessToken = $client->complete( $newuser->requestToken, $verifyCode );
				} catch ( Exception $e ) {
					$newuser->error = $e;
					$newuser->accessToken = null;
					return $newuser;
				}
				unset( $_SESSION[SELF::SESS_RK] );
				unset( $_SESSION[SELF::SESS_RS] );

				session_regenerate_id();

				$_SESSION[SELF::SESS_AK] = $newuser->accessToken->key;
				$_SESSION[SELF::SESS_AS] = $newuser->accessToken->secret;
			} else {
				return $newuser;
			}
		} else {
			$newuser->accessToken = new Token( $_SESSION[SELF::SESS_AK], $_SESSION[SELF::SESS_AS] );
		}

		if ( $check ) {
			try {
				$newuser->info = $client->identify( $newuser->accessToken );
			} catch ( Exception $e ) {
				$newuser->error = $e;
				unset( $_SESSION[SELF::SESS_AK] );
				unset( $_SESSION[SELF::SESS_AS] );
				$newuser->accessToken = null;
			}
		}
		return $newuser;
	}

	/**
	 * Request for a OAuth redirect url
	 *
	 * @return string redirect url
	 */
	public function requestOAuth () {
		if ( session_status() != PHP_SESSION_ACTIVE ) return false;
		try {
			$return = $this->client->initiate();
		} catch ( Exception $e ) {
			$this->error = $e;
			$return = null;
		}
		if ( is_null( $return ) ) return false;

		list( $url, $this->requestToken ) = $return;
		$this->accessToken = null;
		unset( $_SESSION[SELF::SESS_AK] );
		unset( $_SESSION[SELF::SESS_AS] );

		session_regenerate_id();

		$_SESSION[SELF::SESS_RK] = $this->requestToken->key;
		$_SESSION[SELF::SESS_RS] = $this->requestToken->secret;
		return $url;
	}

	/**
	 * Make a signed request to MediaWiki, Token auto provided
	 *
	 * @param string $url URL to call
	 * @param bool $isPost true if this should be a POST request
	 * @param array $postFields POST parameters, only if $isPost is also true
	 * @return string / null Body from the curl request or null if the request is invalid
	 */
	public function requestApi ( $url, $isPost = false, array $postFields = null ) {
		if ( $this->valid() ) {
			try {
				return $this->client->makeOAuthCall( $this->accessToken, $url, $isPost, $postFields );
			} catch ( Exception $e ) {
				$this->error = $e;
				return null;
			}
		} else {
			return null;
		}
	}

	public function getRequestToken () {
		return $this->requestToken;
	}

	public function getAccessToken () {
		return $this->accessToken;
	}

	/**
	 * @return bool Is this user valid
	 */
	public function valid () {
		return $this->accessToken instanceof Token;
	}

	/**
	 * @return bool Is this user valid with basic info
	 */
	public function checked () {
		return $this->accessToken instanceof Token && !is_null( $this->info );
	}

	/**
	 * Kill this Authentication, delete all related session
	 *
	 * @return bool Success or not
	 */
	public function kill () {
		if ( session_status() != PHP_SESSION_ACTIVE ) return false;
		unset( $_SESSION[SELF::SESS_RK] );
		unset( $_SESSION[SELF::SESS_RS] );
		unset( $_SESSION[SELF::SESS_AK] );
		unset( $_SESSION[SELF::SESS_AS] );

		session_regenerate_id();
		
		$this->info = null;
		$this->requestToken = null;
		$this->accessToken = null;
		return true;
	}

}
