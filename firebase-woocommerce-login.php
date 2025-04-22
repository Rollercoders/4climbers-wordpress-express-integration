<?php
/**
 * Plugin Name: Firebase WooCommerce Login
 * Description: Login a WooCommerce user via Firebase Authentication.
 * Version: 1.0.0
 * Author: ChatGPT
 */

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

add_action('rest_api_init', function () {
    register_rest_route('firebase/v1', '/login', [
        'methods' => 'POST',
        'callback' => 'firebase_login_wp',
        'permission_callback' => '__return_true',
    ]);
});

function firebase_login_wp($request) {
    $idToken = $request->get_param('idToken');
    if (!$idToken) {
        return new WP_Error('no_token', 'Token mancante', ['status' => 400]);
    }

    require_once __DIR__ . '/vendor/autoload.php'; // Assicurati che Firebase SDK sia installato qui

    try {
        $firebase = (new \Kreait\Firebase\Factory())
            ->withServiceAccount(__DIR__ . '/firebase_credentials.json');

        $auth = $firebase->createAuth();
        $verified = $auth->verifyIdToken($idToken);

        $email = $verified->claims()->get('email');
        $name = $verified->claims()->get('name');

        if (!$email) {
            return new WP_Error('no_email', 'Email non trovata nel token', ['status' => 400]);
        }

        $user = get_user_by('email', $email);
        if (!$user) {
            $username = sanitize_user(current(explode('@', $email)));
            $user_id = wp_create_user($username, wp_generate_password(), $email);
            wp_update_user([
                'ID' => $user_id,
                'display_name' => $name,
            ]);
            $user = get_user_by('ID', $user_id);
        }

        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        return ['success' => true];
    } catch (Exception $e) {
        return new WP_Error('firebase_error', $e->getMessage(), ['status' => 403]);
    }
}
