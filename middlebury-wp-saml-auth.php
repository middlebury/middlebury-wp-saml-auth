<?php
/**
 * Plugin Name: Middlebury WP SAML Auth
 * Plugin URI: http://sites.middlebury.edu
 * Description: Provides filters and actions to configure the wp-saml-auth module and manage users.
 * Version: 1.0
 * Author: Adam Franco
 * Author URI: http://sites.middlebury.edu
 */

/**
 * Set default options to configure the wp-saml-auth module.
 */
function middlebury_wp_saml_filter_option( $value, $option_name ) {
  if (!defined('MIDDLEBURY_WP_SAML__ENTITY_ID') || empty(MIDDLEBURY_WP_SAML__ENTITY_ID)) {
    throw new Exception('MIDDLEBURY_WP_SAML__ENTITY_ID must be configured.');
  }
  if (!defined('MIDDLEBURY_WP_SAML__SINGLE_SIGN_ON_URL') || empty(MIDDLEBURY_WP_SAML__SINGLE_SIGN_ON_URL)) {
    throw new Exception('MIDDLEBURY_WP_SAML__SINGLE_SIGN_ON_URL must be configured.');
  }
  if (!defined('MIDDLEBURY_WP_SAML__SINGLE_LOG_OUT_URL') || empty(MIDDLEBURY_WP_SAML__SINGLE_LOG_OUT_URL)) {
    throw new Exception('MIDDLEBURY_WP_SAML__SINGLE_LOG_OUT_URL must be configured.');
  }
  if (!defined('MIDDLEBURY_WP_SAML__X509_CERT') || empty(MIDDLEBURY_WP_SAML__X509_CERT)) {
    throw new Exception('MIDDLEBURY_WP_SAML__X509_CERT must be configured.');
  }

  $defaults = array(
    /**
     * Type of SAML connection bridge to use.
     *
     * 'internal' uses OneLogin bundled library; 'simplesamlphp' uses SimpleSAMLphp.
     *
     * Defaults to SimpleSAMLphp for backwards compatibility.
     *
     * @param string
     */
    'connection_type' => 'internal',
    /**
     * Configuration options for OneLogin library use.
     *
     * See comments with "Required:" for values you absolutely need to configure.
     *
     * @param array
     */
    'internal_config'        => array(
      // Validation of SAML responses is required.
      'strict'       => false,
      'debug'        => defined( 'WP_DEBUG' ) && WP_DEBUG ? true : false,
      'baseurl'      => network_site_url('', 'https'),
      'sp'           => array(
        // 'entityId' => 'urn:' . parse_url( home_url(), PHP_URL_HOST ),
        'entityId' => MIDDLEBURY_WP_SAML__ENTITY_ID,
        'assertionConsumerService' => array(
          // Send SAML login requests through our central login URL, then redirect back to target sites/pages.
          'url'  => middlebury_wp_saml_get_login_url(),
          'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        ),
      ),
      'idp'          => array(
        // Required: Set based on provider's supplied value.
        'entityId' => MIDDLEBURY_WP_SAML__ENTITY_ID,
        'singleSignOnService' => array(
          // Required: Set based on provider's supplied value.
          'url'  => MIDDLEBURY_WP_SAML__SINGLE_SIGN_ON_URL,
          'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        ),
        'singleLogoutService' => array(
          // Required: Set based on provider's supplied value.
          'url'  => MIDDLEBURY_WP_SAML__SINGLE_LOG_OUT_URL,
          'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        ),
        // Required: Contents of the IDP's public x509 certificate.
        // Use file_get_contents() to load certificate contents into scope.
        'x509cert' => MIDDLEBURY_WP_SAML__X509_CERT,
        // Optional: Instead of using the x509 cert, you can specify the fingerprint and algorithm.
        'certFingerprint' => '',
        'certFingerprintAlgorithm' => '',
      ),
      'security' => [
        // Set the requestedAuthnContext to false to allow federated sso of guests.
        // The default is to get an AuthContext 'exact' 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'.
        // Guests will have an unspecified auth context.
        'requestedAuthnContext' => false,
      ],
    ),

    /**
     * Whether or not to automatically provision new WordPress users.
     *
     * When WordPress is presented with a SAML user without a
     * corresponding WordPress account, it can either create a new user
     * or display an error that the user needs to contact the site
     * administrator.
     *
     * @param bool
     */
    'auto_provision'         => true,
    /**
     * Whether or not to permit logging in with username and password.
     *
     * If this feature is disabled, all authentication requests will be
     * channeled through SimpleSAMLphp.
     *
     * @param bool
     */
    'permit_wp_login'        => false,
    /**
     * Attribute by which to get a WordPress user for a SAML user.
     *
     * @param string Supported options are 'email' and 'login'.
     */
    'get_user_by'            => 'login',
    /**
     * SAML attribute which includes the user_login value for a user.
     *
     * @param string
     */
    'user_login_attribute'   => 'http://middlebury.edu/MiddleburyCollegeUID',
    /**
     * SAML attribute which includes the user_email value for a user.
     *
     * @param string
     */
    'user_email_attribute'   => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    /**
     * SAML attribute which includes the display_name value for a user.
     *
     * @param string
     */
    'display_name_attribute' => 'http://middlebury.edu/DisplayName',
    /**
     * SAML attribute which includes the first_name value for a user.
     *
     * @param string
     */
    'first_name_attribute' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    /**
     * SAML attribute which includes the last_name value for a user.
     *
     * @param string
     */
    'last_name_attribute' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
    /**
     * Default WordPress role to grant when provisioning new users.
     *
     * @param string
     */
    'default_role'           => get_option( 'default_role' ),
    );
    $value = isset( $defaults[ $option_name ] ) ? $defaults[ $option_name ] : $value;

    // Allow username/password logins to xmlrpc.php as XMLRPC doesn't support SAML.
    // This is needed for the Course Hub to bypass SAML authentication to provision sites.
    if ($option_name == 'permit_wp_login'
      && basename($_SERVER['SCRIPT_NAME']) == 'xmlrpc.php'
      && $_SERVER['R_METHOD'] == 'POST'
    ) {
      $value = TRUE;
    }

    return $value;
}
add_filter( 'wp_saml_auth_option', 'middlebury_wp_saml_filter_option', 10, 2 );


/**
 * Remove the WP-SAML-Auth menu item as it is not user-settable.
 */
function middlebury_wp_saml_remove_menu_items() {
  remove_submenu_page( 'options-general.php', 'wp-saml-auth-settings' );
}
add_action( 'admin_menu', 'middlebury_wp_saml_remove_menu_items', 999 );

/**
 * Prevent users from changing their email addresses -- they must stay with what
 * came through the SAML response as we are using this as a ID.
 *
 * Sources:
 *  https://wordpress.stackexchange.com/a/363376/8660
 *  wpCAS's password change hooks.
 */
class MiddWpSamlAuthDisableMailPasswordChange
{
  public function __construct()
  {
    //prevent email change
    add_action( 'personal_options_update',  [$this, 'disable_mail_change_BACKEND'], 5  );
    add_action( 'show_user_profile',    [$this, 'disable_mail_change_HTML']  );

    // prevent password change.
    add_action('lost_password', [$this, 'disable_function']);
    add_action('retrieve_password', [$this, 'disable_function']);
    add_action('password_reset', [$this, 'disable_function']);
    add_filter('show_password_fields', [$this, 'show_password_fields']);
  }

  public function disable_mail_change_BACKEND($user_id) {
    if ( !current_user_can( 'manage_network_users' ) ) {
      $user = get_user_by('id', $user_id );
      $_POST['email'] = $user->user_email;
    }
  }

  public function disable_mail_change_HTML($user) {
    if ( !current_user_can( 'manage_options' ) ) {
      echo '<script>document.getElementById("email").setAttribute("disabled","disabled"); document.getElementById("email-description").innerHTML = "Email cannot be changed.";</script>';
    }
  }

  // hide password fields on user profile page.
  function show_password_fields( $show_password_fields ) {
    if( 'user-new.php' <> basename( $_SERVER['PHP_SELF'] )) {
      return false;
    }
    $random_password = substr( md5( uniqid( microtime( ))), 0, 8 );

    print '
      <input name="pass1" type="hidden" id="pass1" value="' . $random_password . '" />
      <input name="pass2" type="hidden" id="pass2" value="' . $random_password . '" />';
    return false;
  }

  // disabled reset, lost, and retrieve password features
  function disable_function() {
    die( __( 'Sorry, this feature is disabled.', 'midd-wp-saml-auth' ));
  }
}
new MiddWpSamlAuthDisableMailPasswordChange();

function middlebury_wp_saml_get_login_url() {
  // AzureAD requires login paths to be configured, so we cannot redirect to
  // /<sitename>/wp-login.php for arbitrary <sitename>s. Instead, we'll have
  // AzureAD redirect back to the network /wp-login.php with a redirect parameter
  // to get the user back to the blog/page they were on.
  $login_url = network_site_url('wp-login.php', 'https');

  // Check to see if the current site uses domain mapping. If so, we will need
  // AzureAD to return the user to it otherwise their cookie will be set for the
  // wrong hostname.
  if (!is_main_site()) {
    if (!function_exists('domain_mapping_siteurl')) {
      require_once(WP_PLUGIN_DIR . '/wordpress-mu-domain-mapping/domain_mapping.php');
    }
    $network_hostname = parse_url($login_url, PHP_URL_HOST);
    $site_hostname = parse_url(domain_mapping_siteurl( false ), PHP_URL_HOST);
    if ($site_hostname != $network_hostname) {
      // Set our login URL to be wp-login.php in the root path.
      $login_url = str_replace($network_hostname, $site_hostname, $login_url);
    }
  }
  return $login_url;
}

function middlebury_wp_saml_filter_outgoing_relay_state($redirect_to) {
  $network_login_url = network_site_url('wp-login.php', 'https');
  $network_login_path = parse_url($network_login_url, PHP_URL_PATH);
  $network_login_hostname = parse_url($network_login_url, PHP_URL_HOST);
  $site_login_path = parse_url(site_url('wp-login.php'), PHP_URL_PATH);
  $site_home_url = home_url('', 'https');
  $site_hostname = parse_url($site_home_url, PHP_URL_HOST);

  // The $redirect_to parameter will be our "RelayState" that gets sent to the IdP.
  //
  // Since we are sending to the central /wp-login.php and not the per-site
  // /<sitename>/wp-login.php we need to make sure that the site-version isn't
  // where we are redirecting as that will cause a redirect loop.
  if ($site_login_path != $network_login_path && $redirect_to === $site_login_path) {
    $redirect_to = $site_home_url;
  }
  // If we are using an alternate hostname, be sure to set the full URL in the
  // relay state rather than just '/wp-login.php'.
  elseif ($redirect_to == $network_login_path && $site_hostname != $network_login_hostname) {
    $redirect_to = middlebury_wp_saml_get_login_url();
  }

  return $redirect_to;
}
add_filter( 'wp_saml_auth_filter_outgoing_relay_state', 'middlebury_wp_saml_filter_outgoing_relay_state', 10, 2 );

/**
 * Allows to modify attributes before the SAML authentication.
 *
 * @param array  $attributes All attributes received from the SAML response.
 * @param object $provider   Provider instance currently in use.
 */
function middlebury_wp_saml_auth_attributes($attributes, $provider) {
  if (defined('MIDDLEBURY_SAML_AUTH_LOG_LOGINS') && MIDDLEBURY_SAML_AUTH_LOG_LOGINS) {
    trigger_error('SAML attras: ' . serialize($attributes), E_USER_NOTICE);
    if (defined('MIDDLEBURY_SAML_AUTH_LOG_FILE') && !empty(MIDDLEBURY_SAML_AUTH_LOG_FILE)) {
      $message = date('c') . ' ' . $_SERVER['REMOTE_ADDR'] . ' ' . (empty($_SERVER['HTTP_X_FORWARDED_FOR'])?'':$_SERVER['HTTP_X_FORWARDED_FOR']) . ' ' . serialize($attributes) . "\n";
      file_put_contents(MIDDLEBURY_SAML_AUTH_LOG_FILE, $message, FILE_APPEND);
    }
  }
  return $attributes;
}
add_filter( 'wp_saml_auth_attributes', 'middlebury_wp_saml_auth_attributes', 10, 2 );
